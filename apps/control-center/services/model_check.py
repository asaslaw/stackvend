"""OPEN-MODEL-SETTINGS (owner 11-10): the live model check of a Settings save.

When an administrator changes a model field (or the thinking level of a role), PUT /api/settings makes one small
real `generate_content` call per changed model, through the same client the agents build (the AI Studio key when
GEMINI_API_KEY is mounted, else Vertex AI on GEMINI_LOCATION) and with that role's real request rules
(shared.gemini_model_config.adapt_generate_config_kwargs). The save is stored only when every call is accepted.

A model id that is not in the built-in family table (MODEL_FAMILIES) gets its request style from typed API outcomes,
never from its name: first the budget style (a thinking budget plus the sampling parameters, which is what every
budget-family call sends: repair and the typed-IaC junior always send a budget), then the level style (a thinking
level, no budget, no sampling or penalty parameters). Both probes use the developer's request rules (generation;
PROBE_PURPOSE). The first style the API accepts is stored in `models.custom_families`; when neither is accepted the
save is refused with both errors. A model that accepts a thinking budget is stored as BUDGET even if it would also
take a level: thinking levels then do not apply to it (logged at WARNING, shown on the Settings page).

Re-probe rule (RT F3): a custom id is probed again whenever a save changes any field that names it (or adds it to the
fallback list), so its stored style is refreshed; a field that did not change keeps the stored style without a call.
A role whose thinking level changed re-checks its level-style models with the stored style.

Limits per save (RT F2): at most MAX_FALLBACK_MODELS fallback models (FALLBACK_MODELS_TOO_MANY) and at most
MAX_CHECKS_PER_SAVE checks (MODEL_CHECK_TOO_MANY), both refused before any call; at most MAX_WORKERS calls at once.

Every refusal is a ModelCheckError with a typed code: MODEL_CHECK_FAILED (the API refused the request; Google's
message, trimmed, with no credential), MODEL_CHECK_TIMEOUT (no answer in time: never a pass) or
MODEL_CHECK_UNAVAILABLE (no client could be built). No call is made for a field that did not change.
"""
from __future__ import annotations

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from shared.gemini_model_config import (STYLE_BUDGET, STYLE_LEVEL, Purpose, ThinkingControl,  # noqa: F401
                                        adapt_generate_config_kwargs, canonical_model_id, is_model_id_syntax,
                                        known_model_id, resolve_model_family, thinking_config_for)

logger = logging.getLogger("control-center-model-check")

MODEL_CHECK_FAILED = "MODEL_CHECK_FAILED"
MODEL_CHECK_TIMEOUT = "MODEL_CHECK_TIMEOUT"
MODEL_CHECK_UNAVAILABLE = "MODEL_CHECK_UNAVAILABLE"
MODEL_CHECK_TOO_MANY = "MODEL_CHECK_TOO_MANY"
FALLBACK_MODELS_TOO_MANY = "FALLBACK_MODELS_TOO_MANY"

CHECK_TIMEOUT_SECONDS = 20.0          # the whole check of one save; a Settings save never hangs longer
PROBE_PROMPT = "Reply with OK."
PROBE_MAX_OUTPUT_TOKENS = 256         # room for a LOW thinking level or the probe budget plus a short answer
PROBE_THINKING_BUDGET = 128           # budget style probe: the smallest budget every budget-family model accepts
ERROR_TEXT_MAX_CHARS = 400
MAX_FALLBACK_MODELS = 4               # each new entry is one paid call at save
MAX_CHECKS_PER_SAVE = 10              # 5 model fields + 4 fallbacks + 1 spare; refused above, before any call
MAX_WORKERS = 8                       # calls in flight at once
PROBE_PURPOSE = Purpose.DEVELOPER     # the request rules a custom id's style is probed with
# The style a not-yet-checked id is admitted with while the rest of a PUT body is validated (routes/settings.py);
# the live check replaces it before anything is stored.
PROVISIONAL_STYLE = STYLE_BUDGET

# The purpose each model field is called with (the request rules and thinking level of that role). The fallback
# models stand in for every role; they are checked with the developer's (generation) rules.
FIELD_PURPOSE: Dict[str, Purpose] = {
    "architect_model": Purpose.ARCHITECT,
    "developer_model": Purpose.DEVELOPER,
    "repair_model": Purpose.REPAIR,
    "finops_model": Purpose.AUXILIARY,
    "assistant_model": Purpose.AUXILIARY,
    "fallback_models": Purpose.DEVELOPER,
}


class ModelCheckError(Exception):
    """A refused Settings save: one entry per model that failed its check."""

    def __init__(self, code: str, failures: List[Dict[str, Any]]):
        self.code = code
        self.failures = failures
        super().__init__(f"{code}: " + "; ".join(f"{f['field']}={f['model']!r}: {f['msg']}" for f in failures))

    def detail(self) -> Dict[str, Any]:
        n = len(self.failures)
        what = {MODEL_CHECK_FAILED: "refused by the model API", MODEL_CHECK_TIMEOUT: "did not answer in time",
                MODEL_CHECK_UNAVAILABLE: "could not be checked", MODEL_CHECK_TOO_MANY: "is one check too many",
                FALLBACK_MODELS_TOO_MANY: "is too long"}.get(self.code, "failed its check")
        first = self.failures[0] if self.failures else {}
        return {
            "code": self.code,
            "message": (f"{first.get('field')} = {first.get('model')!r} {what}: {first.get('msg')}"
                        + (f" (and {n - 1} more)" if n > 1 else "") + ". Nothing was saved."),
            "errors": [{"loc": ["models", f["field"]], "msg": f["msg"], "type": self.code, "model": f["model"]}
                       for f in self.failures],
        }


@dataclass
class _Check:
    model: str
    purpose: Purpose
    fields: List[str] = field(default_factory=list)
    style: Optional[str] = None   # None: not in the table or the stored custom families -> probed


def _secret_values() -> List[str]:
    key = os.getenv("GEMINI_API_KEY") or ""
    return [key] if len(key) >= 8 else []


def error_text(err: BaseException) -> str:
    """Google's error as one short line: the API's status and message for an APIError, else the exception type and
    text. The configured API key never appears (its exact value is removed); trimmed to ERROR_TEXT_MAX_CHARS."""
    code = getattr(err, "code", None)
    message = getattr(err, "message", None)
    status = getattr(err, "status", None)
    if isinstance(code, int) and isinstance(message, str):
        text = f"HTTP {code}{(' ' + status) if isinstance(status, str) and status else ''}: {message}"
    else:
        text = f"{type(err).__name__}: {err}"
    for secret in _secret_values():
        text = text.replace(secret, "[redacted]")
    text = " ".join(text.split())
    return text if len(text) <= ERROR_TEXT_MAX_CHARS else text[: ERROR_TEXT_MAX_CHARS - 3] + "..."


def default_client_factory(timeout_seconds: float) -> Any:
    """The client the agents build: the AI Studio key when GEMINI_API_KEY is set, else Vertex AI in the platform
    project on GEMINI_LOCATION (VERTEX_LOCATION, else global). Raises ModelCheckError(UNAVAILABLE) when neither."""
    from google import genai
    from google.genai import types

    http_options = types.HttpOptions(timeout=int(max(1.0, timeout_seconds) * 1000))
    key = os.getenv("GEMINI_API_KEY")
    if key:
        return genai.Client(api_key=key, http_options=http_options)
    project = os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT")
    if not project:
        raise ModelCheckError(MODEL_CHECK_UNAVAILABLE, [{"field": "models", "model": "",
                                                         "msg": "no PROJECT_ID and no GEMINI_API_KEY"}])
    location = os.getenv("GEMINI_LOCATION") or os.getenv("VERTEX_LOCATION", "global")
    return genai.Client(vertexai=True, project=project, location=location, http_options=http_options)


def _referenced(models: Any) -> List[Tuple[str, str]]:
    """(field, model id) of every non-empty model field of an AgentModelSettings-like object."""
    out: List[Tuple[str, str]] = []
    for f in FIELD_PURPOSE:
        if f == "fallback_models":
            out += [(f, m) for m in (getattr(models, f, None) or []) if isinstance(m, str) and m.strip()]
        else:
            v = getattr(models, f, None)
            if isinstance(v, str) and v.strip():
                out.append((f, v))
    return out


def referenced_custom_ids(models: Any) -> List[str]:
    """Canonical ids of the model fields that are not in the built-in table (they need a stored style)."""
    return sorted({canonical_model_id(m) for _, m in _referenced(models) if known_model_id(m) is None})


def check_limits(new: Any) -> None:
    """RT F2: refuse a save that lists more than MAX_FALLBACK_MODELS fallback models (before any call). Checked where
    the settings are saved, not in the schema, so a longer stored list never makes the settings unreadable."""
    fallbacks = [m for m in (getattr(new, "fallback_models", None) or []) if isinstance(m, str) and m.strip()]
    if len(fallbacks) > MAX_FALLBACK_MODELS:
        raise ModelCheckError(FALLBACK_MODELS_TOO_MANY, [{
            "field": "fallback_models", "model": ", ".join(fallbacks),
            "msg": f"{len(fallbacks)} fallback models; at most {MAX_FALLBACK_MODELS} (each new one is a live call "
                   "when the settings are saved)"}])


def plan_checks(old: Any, new: Any, stored_custom_families: Mapping[str, str]) -> List[_Check]:
    """The calls a save needs: every model field whose value changed (a fallback list: its new entries), every
    level-style model of a role whose thinking level changed (with its stored style), and every custom id whose field
    changed or that has no stored style (probed again with PROBE_PURPOSE: RT F3). Unchanged fields are never
    re-checked."""
    old_levels = dict(getattr(old, "thinking_levels", None) or {})
    new_levels = dict(getattr(new, "thinking_levels", None) or {})
    changed_purposes = {p for p in Purpose if old_levels.get(p.value) != new_levels.get(p.value)}
    old_fallbacks = {canonical_model_id(m) for m in (getattr(old, "fallback_models", None) or [])}
    checks: Dict[Tuple[str, Purpose], _Check] = {}

    def style_of(model: str) -> Optional[str]:
        fam = resolve_model_family(model, custom_families=stored_custom_families)
        if fam is None:
            return None
        return STYLE_LEVEL if fam.thinking is ThinkingControl.LEVEL else STYLE_BUDGET

    for f, model in _referenced(new):
        purpose = FIELD_PURPOSE[f]
        style = style_of(model)
        if f == "fallback_models":
            changed = canonical_model_id(model) not in old_fallbacks
        else:
            changed = canonical_model_id(getattr(old, f, "") or "") != canonical_model_id(model)
        level_changed = style == STYLE_LEVEL and purpose in changed_purposes
        custom = known_model_id(model) is None
        # a custom id with no stored style cannot be used until it is checked, changed or not
        if not (changed or level_changed or style is None):
            continue
        if custom and (changed or style is None):
            # RT F3/F6: (re)probe the style, keyed and run with the same purpose
            key = (canonical_model_id(model), PROBE_PURPOSE)
            chk = checks.setdefault(key, _Check(model=model, purpose=PROBE_PURPOSE, style=None))
        else:
            key = (canonical_model_id(model), purpose)
            chk = checks.setdefault(key, _Check(model=model, purpose=purpose, style=style))
        if f not in chk.fields:
            chk.fields.append(f)
    return list(checks.values())


def _call(client: Any, types: Any, model: str, kwargs: Dict[str, Any]) -> None:
    client.models.generate_content(model=model, contents=PROBE_PROMPT,
                                   config=types.GenerateContentConfig(**kwargs))


def _style_kwargs(model: str, style: str, purpose: Purpose, thinking_levels: Mapping[str, str],
                  types: Any) -> Dict[str, Any]:
    """The role's real request config for `model` under `style` (adapt_generate_config_kwargs with that family)."""
    families = {canonical_model_id(model): style}
    base: Dict[str, Any] = {"max_output_tokens": PROBE_MAX_OUTPUT_TOKENS, "temperature": 0.2}
    tc = thinking_config_for(model, PROBE_THINKING_BUDGET, purpose, types=types, custom_families=families,
                             thinking_levels=thinking_levels)
    if tc is not None:
        base["thinking_config"] = tc
    return adapt_generate_config_kwargs(model, purpose, base, types=types, custom_families=families,
                                        thinking_levels=thinking_levels)


def _run_one(chk: _Check, client: Any, types: Any, thinking_levels: Mapping[str, str]) -> Tuple[Optional[str], str]:
    """(style accepted, "") or (None, error text). A table / stored model is called once with its own style; a new
    custom model is probed budget style first, then level style."""
    styles = [chk.style] if chk.style is not None else [STYLE_BUDGET, STYLE_LEVEL]
    errors: List[str] = []
    for style in styles:
        try:
            _call(client, types, chk.model, _style_kwargs(chk.model, style, chk.purpose, thinking_levels, types))
            return style, ""
        except Exception as e:  # noqa: BLE001 - every refusal is reported with the API's own message
            errors.append((f"{style.lower()} style: " if chk.style is None else "") + error_text(e))
    return None, " | ".join(errors)


def run_checks(checks: Iterable[_Check], *, thinking_levels: Mapping[str, str],
               client_factory: Optional[Callable[[float], Any]] = None,
               timeout_seconds: Optional[float] = None,
               types: Any = None) -> Dict[str, str]:
    """Run the planned calls concurrently under one deadline. Returns {canonical id: style} of the newly probed
    custom models. Raises ModelCheckError: FAILED (any refusal), TIMEOUT (any call unanswered at the deadline) or
    UNAVAILABLE (no client)."""
    checks = list(checks)
    if not checks:
        return {}
    if len(checks) > MAX_CHECKS_PER_SAVE:
        raise ModelCheckError(MODEL_CHECK_TOO_MANY, [
            {"field": f, "model": c.model, "msg": f"{len(checks)} model checks in one save; at most "
                                                  f"{MAX_CHECKS_PER_SAVE}"} for c in checks for f in c.fields])
    timeout_seconds = CHECK_TIMEOUT_SECONDS if timeout_seconds is None else float(timeout_seconds)
    if types is None:
        from google.genai import types as _types
        types = _types
    try:
        client = (client_factory or default_client_factory)(timeout_seconds)
    except ModelCheckError:
        raise
    except Exception as e:  # noqa: BLE001 - no client = nothing could be checked: refused, never a pass
        raise ModelCheckError(MODEL_CHECK_UNAVAILABLE, [{"field": f, "model": c.model, "msg": error_text(e)}
                                                        for c in checks for f in c.fields])
    started = time.monotonic()
    pool = ThreadPoolExecutor(max_workers=min(len(checks), MAX_WORKERS), thread_name_prefix="model-check")
    try:
        futures = {pool.submit(_run_one, c, client, types, thinking_levels): c for c in checks}
        done, not_done = wait(futures, timeout=timeout_seconds)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    if not_done:
        waited = round(time.monotonic() - started, 1)
        raise ModelCheckError(MODEL_CHECK_TIMEOUT, [
            {"field": f, "model": futures[fu].model, "msg": f"no answer within {waited} s"}
            for fu in not_done for f in futures[fu].fields])
    failures: List[Dict[str, Any]] = []
    probed: Dict[str, str] = {}
    for fu in done:
        c = futures[fu]
        style, err = fu.result()
        if style is None:
            failures += [{"field": f, "model": c.model, "msg": err} for f in c.fields]
        elif c.style is None:
            probed[canonical_model_id(c.model)] = style
    if failures:
        failures.sort(key=lambda x: (list(FIELD_PURPOSE).index(x["field"]) if x["field"] in FIELD_PURPOSE else 99,
                                     x["model"]))
        raise ModelCheckError(MODEL_CHECK_FAILED, failures)
    for c in checks:
        logger.info(f"model check: {c.model!r} accepted for {', '.join(c.fields)}"
                    + (f" (request style {probed[canonical_model_id(c.model)]})" if c.style is None else ""))
        if c.style is None and probed.get(canonical_model_id(c.model)) == STYLE_BUDGET:
            # RT F3: budget-first is a policy; say what it means for this model
            logger.warning(f"model check: {c.model!r} accepted a thinking budget and is stored with request style "
                           "BUDGET (Gemini 3.x rules: thinking budget and sampling parameters are sent; the thinking "
                           "levels do not apply to it). It is probed again when a save changes a field naming it.")
    return probed
