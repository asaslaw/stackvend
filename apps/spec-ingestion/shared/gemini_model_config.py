"""Per-model-family Gemini request rules (owner-approved 10-14: Gemini 4 Argon compatibility).

REPLICATED FILE: 8 identical copies live in shared/, apps/{billing-alert-drain,control-center,finops-enforcer,
orchestrator-gateway,project-vending,spec-ingestion}/shared/ and mcp-servers/terraform/shared/ (parity:
tests/test_argon_compat.py, tests/test_gemini_4_carbon.py). Edit all.

Gemini <= 3.x takes `ThinkingConfig(thinking_budget=N)` and honours temperature/top_p/top_k. Gemini 4 Argon
(`gemini-4-argon`, Vertex locations global/us/eu) rejects `thinking_budget`, MINIMAL thinking, candidate_count,
frequency/presence penalties and explicit cached_content with HTTP 400, silently ignores temperature/top_p/top_k,
counts thinking inside max_output_tokens and caps non-streaming output at 32,768 tokens (long decode needs v1beta1).
Gemini 4 Carbon (`gemini-4-carbon`, GA on Vertex global/us; owner 11-10, register row GEMINI-4-CARBON) takes the
same request rules as Argon under its own family entry (probed 11-10: thinking_budget, MINIMAL thinking and the
penalty params answer HTTP 400; thinking_level LOW/MEDIUM is accepted).

The family of a model id comes from the explicit table below (exact ids, plus `<known id>-<suffix>` for a versioned
or preview build of a known id; a `publishers/google/models/` path prefix is stripped). Nothing is inferred from a
substring. OPEN-MODEL-SETTINGS (owner 11-10): an id that is not in the table may still be used when the platform
settings store its request style (`models.custom_families`: LEVEL or BUDGET, written by the Control Center's live
check of the save, from typed API outcomes). The table always wins. An id in neither is refused with
UNSUPPORTED_MODEL_CONFIG where settings are saved or loaded (`validate_model_id`); a live call never raises for it --
it is sent exactly as before this module existed.

The thinking level of a level-family call comes from `models.thinking_levels` (THINKING-LEVEL-SETTINGS, owner 11-10:
per role, LOW/MEDIUM/HIGH); a role without a value uses ARGON_THINKING_LEVEL. Both settings are read through
shared/settings.py `get_platform_settings` (cached) only when a call needs them: a table model's family and every
budget-family request never read the settings. A caller may pass `custom_families` / `thinking_levels` explicitly
(the Control Center's save check does, with the values being saved).

For a budget-family model every function here returns its input unchanged (Flash requests stay byte-identical;
tests/fixtures/argon_flash_request_configs.json).

DEFAULT-MODEL-GEMINI-4-CARBON (owner 11-11): DEFAULT_PRIMARY_MODEL (gemini-4-carbon) is the code default of every
model role and DEFAULT_FALLBACK_MODELS the default fallback list (DEFAULT-FALLBACK-CHAIN, owner 11-13: gemini-4-argon,
gemini-3.8-flash, gemini-3.7-flash); shared/settings.py takes both from here. Stored settings are never rewritten: an install keeps the models its settings name.

Vertex location (same row): Argon and Carbon are not served by every Vertex location, so VERTEX_LOCATIONS lists, per
family name, the locations proven to serve it (today `global` only, live-probed 11-11). `vertex_location_for(model,
configured)` returns the configured location when the model's family is served there (or has no entry: Gemini 3.x and
stored custom styles keep the configured location), else VERTEX_GLOBAL_LOCATION, which every entry includes. An empty
configured location is `global` for every model. Exact family lookup, no substring.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, FrozenSet, Iterable, Mapping, Optional

logger = logging.getLogger("castor-gemini-model-config")

__all__ = ["UNSUPPORTED_MODEL_CONFIG", "UnsupportedModelConfig", "Purpose", "ThinkingControl", "ModelFamily",
           "BUDGET_FAMILY", "ARGON_FAMILY", "CARBON_FAMILY", "MODEL_FAMILIES", "ARGON_THINKING_LEVEL",
           "THINKING_RESERVE_TOKENS", "SAMPLING_PARAMS", "STYLE_LEVEL", "STYLE_BUDGET", "REQUEST_STYLES",
           "LEVEL_STYLE_FAMILY", "STYLE_FAMILIES", "THINKING_LEVELS", "DEFAULT_THINKING_LEVELS",
           "MODEL_ID_MAX_LENGTH", "is_model_id_syntax", "canonical_model_id", "known_model_id",
           "resolve_model_family", "validate_model_id", "validate_model_ids", "validate_custom_families",
           "validate_thinking_levels", "thinking_level_for", "thinking_config_for", "max_output_tokens_for",
           "adapt_generate_config_kwargs", "sdk_supports_thinking_level", "assert_sdk_supports_families",
           "DEFAULT_PRIMARY_MODEL", "DEFAULT_FALLBACK_MODELS", "VERTEX_GLOBAL_LOCATION", "VERTEX_LOCATIONS",
           "vertex_location_for"]

UNSUPPORTED_MODEL_CONFIG = "UNSUPPORTED_MODEL_CONFIG"


class UnsupportedModelConfig(ValueError):
    """Typed refusal of a model id / SDK combination this platform has no request rules for."""
    code = UNSUPPORTED_MODEL_CONFIG

    def __init__(self, detail: str):
        super().__init__(f"{UNSUPPORTED_MODEL_CONFIG}: {detail}")
        self.detail = detail


class ThinkingControl(str, Enum):
    BUDGET = "thinking_budget"
    LEVEL = "thinking_level"


class Purpose(str, Enum):
    ARCHITECT = "architect"    # DAG generation, topology patch call, red-team critic
    REPAIR = "repair"          # hallucination-stack repair call
    DEVELOPER = "developer"    # code generation (single turn, swarm juniors, lead WBS)
    AUXILIARY = "auxiliary"    # judge, compliance, CC assistant, domain sub-plan


@dataclass(frozen=True)
class ModelFamily:
    name: str
    thinking: ThinkingControl
    # None: the request's max_output_tokens is sent unchanged; an int: the non-streaming output cap of the family
    non_streaming_max_output_tokens: Optional[int]
    sampling_params_honoured: bool             # temperature / top_p / top_k
    rejected_params: FrozenSet[str]            # GenerateContentConfig fields the API answers with HTTP 400


BUDGET_FAMILY = ModelFamily(name="gemini<=3.x", thinking=ThinkingControl.BUDGET, non_streaming_max_output_tokens=None,
                            sampling_params_honoured=True, rejected_params=frozenset())
ARGON_FAMILY = ModelFamily(name="gemini-4-argon", thinking=ThinkingControl.LEVEL,
                           non_streaming_max_output_tokens=32_768, sampling_params_honoured=False,
                           rejected_params=frozenset({"candidate_count", "frequency_penalty", "presence_penalty",
                                                      "cached_content"}))
# Gemini 4 Carbon (owner 11-10, GEMINI-4-CARBON): Argon's rules under its own name. 32,768 = Argon's non-streaming
# cap, kept until Carbon's own long-output cap is measured.
CARBON_FAMILY = ModelFamily(name="gemini-4-carbon", thinking=ARGON_FAMILY.thinking,
                            non_streaming_max_output_tokens=ARGON_FAMILY.non_streaming_max_output_tokens,
                            sampling_params_honoured=ARGON_FAMILY.sampling_params_honoured,
                            rejected_params=ARGON_FAMILY.rejected_params)

MODEL_FAMILIES: Dict[str, ModelFamily] = {
    "gemini-1.5-flash": BUDGET_FAMILY,
    "gemini-1.5-pro": BUDGET_FAMILY,
    "gemini-2.0-flash": BUDGET_FAMILY,
    "gemini-2.0-flash-lite": BUDGET_FAMILY,
    "gemini-2.5-flash": BUDGET_FAMILY,
    "gemini-2.5-flash-lite": BUDGET_FAMILY,
    "gemini-2.5-pro": BUDGET_FAMILY,
    "gemini-3.0-flash": BUDGET_FAMILY,
    "gemini-3.7-flash": BUDGET_FAMILY,
    "gemini-3.8-flash": BUDGET_FAMILY,
    "gemini-3.8-pro": BUDGET_FAMILY,
    "gemini-4-argon": ARGON_FAMILY,
    "gemini-4-carbon": CARBON_FAMILY,
}

# DEFAULT-MODEL-GEMINI-4-CARBON (owner 11-11: "i want to default stackvend to ... gemini-4-carbon. It is just
# superior."; "gemini-4-argon should be the fall back"): the code default of every model role and the default
# fallback list (shared/settings.py AgentModelSettings and get_model_cascade_for_agent). New installs only: stored
# settings keep their models.
DEFAULT_PRIMARY_MODEL = "gemini-4-carbon"
# DEFAULT-FALLBACK-CHAIN (owner 11-13: "yes, make that the default for new installs too"): Argon, then the two Flash
# models (separate capacity when the Gemini 4 models are overloaded). New installs only, like the primary.
DEFAULT_FALLBACK_MODELS = ("gemini-4-argon", "gemini-3.8-flash", "gemini-3.7-flash")

# Vertex AI locations PROVEN to serve a family, keyed by ModelFamily.name (exact). A family without an entry (Gemini
# 3.x, a stored custom style) is called on the configured location unchanged. Every entry includes the global
# endpoint. Only probed locations are listed (RT F5, live probe 11-11: `global` answers 200 for Argon and Carbon; the
# `us` multi-region endpoint answered 400 and the `us`/`eu` regional-endpoint hosts did not resolve), so a configured
# us / eu / regional location sends these models to `global`.
VERTEX_GLOBAL_LOCATION = "global"
VERTEX_LOCATIONS: Dict[str, FrozenSet[str]] = {
    ARGON_FAMILY.name: frozenset({VERTEX_GLOBAL_LOCATION}),
    CARBON_FAMILY.name: frozenset({VERTEX_GLOBAL_LOCATION}),
}

# OPEN-MODEL-SETTINGS (owner 11-10): the request style stored for a model that is not in MODEL_FAMILIES. LEVEL = the
# Gemini 4 rules (Argon's: thinking level, no budget, no sampling / penalty params, 32,768 non-streaming cap until
# measured); BUDGET = the Gemini <= 3.x rules (requests unchanged).
STYLE_LEVEL = "LEVEL"
STYLE_BUDGET = "BUDGET"
REQUEST_STYLES = (STYLE_LEVEL, STYLE_BUDGET)
LEVEL_STYLE_FAMILY = ModelFamily(name="custom-level-style", thinking=ThinkingControl.LEVEL,
                                 non_streaming_max_output_tokens=ARGON_FAMILY.non_streaming_max_output_tokens,
                                 sampling_params_honoured=False, rejected_params=ARGON_FAMILY.rejected_params)
STYLE_FAMILIES: Dict[str, ModelFamily] = {STYLE_LEVEL: LEVEL_STYLE_FAMILY, STYLE_BUDGET: BUDGET_FAMILY}
MODEL_ID_MAX_LENGTH = 80
_MODEL_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")

# Argon thinking level per call purpose (owner 10-14: architect/repair LOW for bounded latency and output,
# developer generation MEDIUM = the model default). MINIMAL is rejected by Argon and never used. Used for every
# level family (Argon and Carbon) when the settings give no level for the role (THINKING-LEVEL-SETTINGS).
ARGON_THINKING_LEVEL: Dict[Purpose, str] = {
    Purpose.ARCHITECT: "LOW",
    Purpose.REPAIR: "LOW",
    Purpose.DEVELOPER: "MEDIUM",
    Purpose.AUXILIARY: "LOW",
}
# THINKING-LEVEL-SETTINGS (owner 11-10): the levels an administrator may set per role. MINIMAL is refused (Gemini 4
# answers it with HTTP 400). The settings default is exactly ARGON_THINKING_LEVEL.
THINKING_LEVELS = ("LOW", "MEDIUM", "HIGH")
DEFAULT_THINKING_LEVELS: Dict[str, str] = {p.value: level for p, level in ARGON_THINKING_LEVEL.items()}
# Output tokens reserved for thinking at a level (Argon has no budget; thinking counts inside max_output_tokens).
# Estimates until measured on castor (handoff argon-compat-report.md, owner action).
THINKING_RESERVE_TOKENS: Dict[str, int] = {"LOW": 4096, "MEDIUM": 8192, "HIGH": 16384}

SAMPLING_PARAMS = ("temperature", "top_p", "top_k")
_PATH_PREFIXES = ("publishers/google/models/", "models/")
_warned_unknown: set = set()
_warned_capped: set = set()
_warned_location: set = set()


def _canonical_id(model: Any) -> str:
    mid = str(model or "").strip().lower()
    for prefix in _PATH_PREFIXES:
        if mid.startswith(prefix):
            mid = mid[len(prefix):]
    return mid


def canonical_model_id(model: Any) -> str:
    """The id rule's canonical form (lower case, path prefix stripped): the key of `models.custom_families`."""
    return _canonical_id(model)


def is_model_id_syntax(model: Any) -> bool:
    """A model id an administrator may enter: letters, digits, dots and hyphens, 1..MODEL_ID_MAX_LENGTH characters,
    starting with a letter or digit."""
    return (isinstance(model, str) and 0 < len(model) <= MODEL_ID_MAX_LENGTH and set(model) <= _MODEL_ID_CHARS
            and model[0].isalnum())


def known_model_id(model: Any) -> Optional[str]:
    """The MODEL_FAMILIES key `model` resolves to (path prefix stripped; exact id, else `<known id>-<suffix>` with
    the longest known id winning), or None. The one id rule for families AND prices (token_accounting.py)."""
    mid = _canonical_id(model)
    if mid in MODEL_FAMILIES:
        return mid
    best = None
    for known in MODEL_FAMILIES:
        if mid.startswith(known + "-") and (best is None or len(known) > len(best)):
            best = known
    return best


def vertex_location_for(model: Any, configured: Any) -> str:
    """The Vertex AI location to call `model` on, given the configured one (GEMINI_LOCATION / VERTEX_LOCATION /
    a region). An empty configured value is VERTEX_GLOBAL_LOCATION for every model. The configured location
    (stripped, lower case) when the model's table family has no VERTEX_LOCATIONS entry or is served there; else
    VERTEX_GLOBAL_LOCATION (logged once per model and location). Only the table family is used: a custom id keeps the
    configured location, where the Control Center's live check of the save reached it."""
    loc = (str(configured or "").strip() or VERTEX_GLOBAL_LOCATION).lower()
    known = known_model_id(model)
    served = VERTEX_LOCATIONS.get(MODEL_FAMILIES[known].name) if known is not None else None
    if served is None or loc in served:
        return loc
    key = (known, loc)
    if key not in _warned_location:
        _warned_location.add(key)
        logger.warning(f"model '{model}' is not served on Vertex location '{loc}' (served: "
                       f"{', '.join(sorted(served))}); called on '{VERTEX_GLOBAL_LOCATION}'")
    return VERTEX_GLOBAL_LOCATION


def _stored_models_section() -> Any:
    """`models` of the platform settings this process reads (shared/settings.py get_platform_settings: cached, never
    raises for a read failure -- it returns the last good settings or the defaults). None when the settings module
    cannot be used at all."""
    try:
        try:
            from shared import settings as _settings
        except ImportError:  # pragma: no cover - vendored as a relative package
            from . import settings as _settings  # type: ignore
        return _settings.get_platform_settings().models
    except Exception as e:  # noqa: BLE001 - no settings: the built-in rules apply (table families, default levels)
        logger.error(f"platform settings unavailable for the model request rules ({type(e).__name__}: {e}); the "
                     "built-in families and default thinking levels apply")
        return None


def _stored_custom_families() -> Mapping[str, str]:
    value = getattr(_stored_models_section(), "custom_families", None)
    return value if isinstance(value, Mapping) else {}


def resolve_model_family(model: Any, custom_families: Optional[Mapping[str, str]] = None) -> Optional[ModelFamily]:
    """The family of `model`: MODEL_FAMILIES first; for an id not in the table, the style stored for it in
    `custom_families` (the given mapping, else the platform settings' `models.custom_families`); else None."""
    known = known_model_id(model)
    if known is not None:
        return MODEL_FAMILIES[known]
    families = _stored_custom_families() if custom_families is None else custom_families
    style = families.get(_canonical_id(model)) if isinstance(families, Mapping) else None
    return STYLE_FAMILIES.get(style) if isinstance(style, str) else None


def validate_model_id(model: Any, field: str = "model",
                      custom_families: Optional[Mapping[str, str]] = None) -> str:
    """Settings save/load gate: "" (use the default), a model id with a family in the table, or (OPEN-MODEL-SETTINGS)
    an id with the entered-id syntax whose request style is in `custom_families` (the settings document's own
    mapping: never read from the stored settings here); else UnsupportedModelConfig."""
    if model is None or str(model).strip() == "":
        return "" if model is None else str(model)
    if known_model_id(model) is not None:
        return str(model)
    families = custom_families if isinstance(custom_families, Mapping) else {}
    if is_model_id_syntax(model) and families.get(_canonical_id(model)) in STYLE_FAMILIES:
        return str(model)
    raise UnsupportedModelConfig(f"{field}={model!r} is not a known Gemini model id (known: "
                                 f"{', '.join(sorted(MODEL_FAMILIES))}; any other id is accepted once the "
                                 "Control Center's live check of the save has stored its request style)")


def validate_model_ids(models: Iterable[Any], field: str = "models",
                       custom_families: Optional[Mapping[str, str]] = None) -> list:
    return [validate_model_id(m, field, custom_families) for m in (models or [])]


def validate_custom_families(value: Any) -> Dict[str, str]:
    """`models.custom_families`: {canonical model id: LEVEL | BUDGET}. Keys must have the entered-id syntax in
    canonical (lower-case) form; values must be a request style."""
    if not isinstance(value, Mapping):
        raise ValueError("custom_families must be a mapping of model id -> LEVEL | BUDGET")
    out: Dict[str, str] = {}
    for k, v in value.items():
        if not is_model_id_syntax(k) or _canonical_id(k) != k:
            raise ValueError(f"custom_families key {k!r} is not a lower-case model id (letters, digits, dots, "
                             f"hyphens; at most {MODEL_ID_MAX_LENGTH} characters)")
        if v not in REQUEST_STYLES:
            raise ValueError(f"custom_families[{k!r}] = {v!r}: must be one of {', '.join(REQUEST_STYLES)}")
        out[k] = v
    return out


def validate_thinking_levels(value: Any) -> Dict[str, str]:
    """`models.thinking_levels`: {role: LOW | MEDIUM | HIGH} for the roles architect, developer, repair and auxiliary.
    MINIMAL is refused (Gemini 4 rejects it). A role left out takes its default (ARGON_THINKING_LEVEL)."""
    if value is None:
        return dict(DEFAULT_THINKING_LEVELS)
    if not isinstance(value, Mapping):
        raise ValueError("thinking_levels must be a mapping of role -> LOW | MEDIUM | HIGH")
    out = dict(DEFAULT_THINKING_LEVELS)
    for k, v in value.items():
        if k not in DEFAULT_THINKING_LEVELS:
            raise ValueError(f"thinking_levels role {k!r}: must be one of {', '.join(DEFAULT_THINKING_LEVELS)}")
        if v not in THINKING_LEVELS:
            raise ValueError(f"thinking_levels[{k!r}] = {v!r}: must be one of {', '.join(THINKING_LEVELS)} "
                             "(MINIMAL is refused by Gemini 4)")
        out[k] = v
    return out


def thinking_level_for(purpose: Purpose, thinking_levels: Optional[Mapping[str, str]] = None) -> str:
    """The thinking level of a level-family call: `thinking_levels[<role>]` (the given mapping, else the platform
    settings' `models.thinking_levels`) when it is LOW/MEDIUM/HIGH, else ARGON_THINKING_LEVEL."""
    p = Purpose(purpose)
    levels = thinking_levels
    if levels is None:
        levels = getattr(_stored_models_section(), "thinking_levels", None)
    level = levels.get(p.value) if isinstance(levels, Mapping) else None
    return level if level in THINKING_LEVELS else ARGON_THINKING_LEVEL[p]


def _family_for_call(model: Any, custom_families: Optional[Mapping[str, str]] = None) -> Optional[ModelFamily]:
    fam = resolve_model_family(model, custom_families)
    if fam is None:
        key = _canonical_id(model)
        if key not in _warned_unknown:
            _warned_unknown.add(key)
            logger.warning(f"{UNSUPPORTED_MODEL_CONFIG}: model '{model}' has no family entry; request sent "
                           "unchanged (settings validation should have refused it)")
    return fam


def sdk_supports_thinking_level(types: Any) -> bool:
    """`types` = the caller's google.genai.types module (this module never imports the SDK: it is vendored into
    services that have no google-genai, tests/test_shared_packaging.py)."""
    try:
        return "thinking_level" in getattr(types.ThinkingConfig, "model_fields", {}) and hasattr(types, "ThinkingLevel")
    except Exception:  # noqa: BLE001
        return False


def assert_sdk_supports_families(models: Iterable[Any], *, types: Any) -> None:
    """Startup gate: every level-family model in `models` needs a google-genai SDK with ThinkingConfig.thinking_level
    (>= 2.30.1 per the Argon guide). Ids that are not in the table raise too."""
    for m in models or []:
        if m is None or str(m).strip() == "":
            continue
        validate_model_id(m)
        if MODEL_FAMILIES[known_model_id(m)].thinking is ThinkingControl.LEVEL and not sdk_supports_thinking_level(types):
            raise UnsupportedModelConfig(f"model {m!r} needs a google-genai with ThinkingConfig.thinking_level "
                                         "(2.29.0 has it; the Argon guide names >= 2.30.1)")


def thinking_config_for(model: Any, budget_tokens: Optional[int], purpose: Purpose, *, types: Any,
                        custom_families: Optional[Mapping[str, str]] = None,
                        thinking_levels: Optional[Mapping[str, str]] = None) -> Any:
    """The ThinkingConfig for one call, or None for "send no thinking_config". `types` = google.genai.types.

    Budget family (and an unknown id): ThinkingConfig(thinking_budget=budget_tokens) when budget_tokens > 0, else
    None -- exactly what every call site sent before. Level family: ThinkingConfig(thinking_level=<the role's level,
    thinking_level_for>); budget_tokens is not sent (Argon answers thinking_budget with HTTP 400)."""
    fam = _family_for_call(model, custom_families)
    if fam is None or fam.thinking is ThinkingControl.BUDGET:
        if hasattr(types, "ThinkingConfig") and budget_tokens is not None and int(budget_tokens) > 0:
            return types.ThinkingConfig(thinking_budget=int(budget_tokens))
        return None
    if not sdk_supports_thinking_level(types):
        # never raise on a live call; the gateway startup gate reports this SDK (assert_sdk_supports_families)
        logger.error(f"{UNSUPPORTED_MODEL_CONFIG}: google-genai has no ThinkingConfig.thinking_level; '{model}' "
                     "called with its default thinking")
        return None
    level = thinking_level_for(purpose, thinking_levels)
    return types.ThinkingConfig(thinking_level=getattr(types.ThinkingLevel, level))


def max_output_tokens_for(model: Any, requested: Optional[int], purpose: Purpose,
                          reserved_thinking_tokens: int = 0, *,
                          custom_families: Optional[Mapping[str, str]] = None,
                          thinking_levels: Optional[Mapping[str, str]] = None) -> Optional[int]:
    """max_output_tokens for one call.

    Budget family / unknown id: `requested` unchanged. Level family: thinking has no budget and counts inside the
    bound, so the `reserved_thinking_tokens` the budget-family bound already set aside is replaced by the reserve of
    the role's level (THINKING_RESERVE_TOKENS: LOW 4,096, MEDIUM 8,192, HIGH 16,384), then capped at the family's
    non-streaming output cap (32,768 for Argon; long decode is not enabled -- see the handoff report). None (the call
    sets no bound) stays None."""
    fam = _family_for_call(model, custom_families)
    if fam is None or fam.thinking is ThinkingControl.BUDGET or requested is None:
        return requested
    level = thinking_level_for(purpose, thinking_levels)
    reserve = THINKING_RESERVE_TOKENS[level]
    answer_room = max(0, int(requested) - max(0, int(reserved_thinking_tokens or 0)))
    out = answer_room + reserve
    cap = fam.non_streaming_max_output_tokens
    if cap is not None and out > cap:
        out = cap
        key = (_canonical_id(model), Purpose(purpose).value, level, int(requested))
        if key not in _warned_capped:   # OPEN-MODEL-SETTINGS RT F5: once per process, with the numbers
            _warned_capped.add(key)
            logger.warning(f"max_output_tokens for '{model}' ({Purpose(purpose).value}, thinking level {level}) capped "
                           f"at {cap}: the {reserve}-token {level} reserve leaves {max(0, cap - reserve)} tokens for "
                           f"the answer instead of the {answer_room} asked")
    return int(out)


def adapt_generate_config_kwargs(model: Any, purpose: Purpose, kwargs: Dict[str, Any], *,
                                 types: Any, custom_families: Optional[Mapping[str, str]] = None,
                                 thinking_levels: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """GenerateContentConfig kwargs (or the dict config) for `model`; `types` = google.genai.types.

    Budget family / unknown id: the SAME dict object, untouched. Level family: a new dict without the sampling
    params (ignored by the model) and the rejected params (HTTP 400), with thinking_config =
    thinking_config_for(model, None, purpose) (any thinking_budget config is replaced) and max_output_tokens capped
    at the family's non-streaming cap."""
    fam = _family_for_call(model, custom_families)
    if fam is None or fam.thinking is ThinkingControl.BUDGET:
        return kwargs
    out = {k: v for k, v in kwargs.items()
           if k not in SAMPLING_PARAMS and k not in fam.rejected_params and k != "thinking_config"}
    tc = thinking_config_for(model, None, purpose, types=types, custom_families=custom_families,
                             thinking_levels=thinking_levels)
    if tc is not None:
        out["thinking_config"] = tc
    cap = fam.non_streaming_max_output_tokens
    if cap is not None and out.get("max_output_tokens") is not None and int(out["max_output_tokens"]) > cap:
        out["max_output_tokens"] = cap
    return out
