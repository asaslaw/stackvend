"""Hallucination-stack settings, Step 1 fields (Wave 2 C0a; integration plan §1.6, Step 1 RT F7).

`HallucinationStackSettings` carries code defaults only. It is wired into the admin-editable `PlatformSettings`
(shared/settings.py, an existing replica) at C0b, after lane 12 Phase 1; until then the gateway reads these defaults,
optionally overridden per process by the runtime that configures the developer stage (gateway startup, eval harness).
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

try:
    from shared.gemini_model_config import (Purpose, ThinkingControl, max_output_tokens_for, resolve_model_family,
                                            validate_model_id)
except ImportError:  # pragma: no cover
    from .gemini_model_config import (Purpose, ThinkingControl, max_output_tokens_for,  # type: ignore
                                      resolve_model_family, validate_model_id)

__all__ = ["HallucinationStackSettings", "DEFAULT_SWARM_TOKEN_ENVELOPE", "MIN_REPAIR_CANDIDATE_TOKENS",
           "effective_repair_token_budget", "effective_dispatch_token_budget", "repair_call_max_output_tokens",
           "repair_call_thinking_budget", "resolve_repair_model"]

DEFAULT_SWARM_TOKEN_ENVELOPE = 350_000   # AgentModelSettings.max_swarm_token_envelope default
MIN_REPAIR_CANDIDATE_TOKENS = 1024       # room left for the JSON answer when the per-call cap binds


class HallucinationStackSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repair_max_iterations_precommit: int = Field(default=3, ge=0, le=10,
                                                 description="repair rounds per developer dispatch")
    # QA-REPAIR-BUDGET (owner 10-29): the per-trace budgets are sized for QA-RETRIES' 3 QA repair rounds (they were
    # 5 / 250_000 / 0.7 for one round): 10 = the first build at its precommit cap (3) + 2 per QA round x 3 + 1 for a
    # deploy-time intent repair; tokens = 2x today's effective budget for every swarm envelope (490_000 at the
    # default 350_000 envelope; one QA repair iteration reserves ~23k-38k tokens: prompt <= ~14k + files to fix,
    # answer <= 16_384).
    repair_max_iterations_total: int = Field(default=10, ge=0, le=20,
                                             description="repair rounds per TRACE incl. apply/qa continuations")
    repair_token_budget: int = Field(default=500_000, ge=0,
                                     description="repair tokens per TRACE incl. thinking tokens; effective = "
                                                 "min(this, repair_budget_envelope_fraction x swarm envelope)")
    repair_budget_envelope_fraction: float = Field(default=1.4, gt=0.0, le=2.0,
                                                   description="per TRACE (all QA rounds), so it may exceed 1.0")
    # QA-REPAIR-BUDGET: one developer dispatch keeps today's token budget (the old per-trace values), so a single-round
    # run (one dispatch on a fresh trace) stops exactly where it stopped before; only later dispatches gain room.
    repair_dispatch_token_budget: int = Field(default=250_000, ge=0,
                                              description="repair tokens per developer DISPATCH; effective = min(this, "
                                                          "repair_dispatch_envelope_fraction x swarm envelope)")
    repair_dispatch_envelope_fraction: float = Field(default=0.7, gt=0.0, le=1.0)
    repair_max_output_tokens: int = Field(default=16_384, ge=1024, le=65_536,
                                          description="per-call cap on candidates + thoughts (Vertex counts thinking "
                                                      "inside max_output_tokens); a call uses min(this, 1.5 x "
                                                      "tokens(files) + 2048 + repair_thinking_budget)")
    repair_thinking_budget: int = Field(default=2048, ge=128, le=16_384,
                                        description="thinking tokens per repair call, sent as ThinkingConfig("
                                                    "thinking_budget); without it the model spent ~96% of the call "
                                                    "bound thinking and the answer was cut off (R3, 10-13)")
    repair_model: str = Field(default="", description='"" -> developer_model (owner decision D1)')
    repair_wall_clock_s: int = Field(default=900, ge=10,
                                     description="per developer dispatch (REPAIR-WALL-CLOCK-900, owner 11-15: was 360; QA-REPAIR-BUDGET: not summed across the "
                                                 "trace; RepairLedger.wall_clock_ms keeps the trace total)")
    remote_validate_timeout_s: int = Field(default=60, ge=5, description="per /validate call")
    validate_ready_wait_s: int = Field(default=180, ge=0, le=900,
                                       description="developer stage: total time to poll the terraform server's "
                                                   "/validate/ready (backoff) before GATE_UNAVAILABLE; 0 = one "
                                                   "probe (owner 10-13, Step 1 follow-up)")
    # TI-3 (typed IaC plan §4): "generate" = the IaC persona fills the typed intent infra/workload/iac_intent.json and
    # the platform renders the workload IaC; "off" = today's HCL contract, every prompt and tree byte-identical.
    # Sticky per workload: a repository that already holds iac_intent.json stays on the intent path whatever this
    # setting says (developer_agent/iac_intent_contract.resolve_iac_intent_mode), so "off" affects new workloads only.
    iac_intent_mode: Literal["off", "generate"] = Field(default="off",
                                                       description="typed IaC intent contract for NEW workloads")
    # TI-3: send the intent's JSON schema as Gemini `response_json_schema` on the IaC persona's calls. Off until the
    # owner-approved schema spike (TI-2 report §6) has shown the API accepts it; the platform gate is the hard check.
    iac_intent_structured_output: bool = Field(default=False,
                                               description="intent mode only: response_json_schema on IaC calls")
    # TI-3 smoke cost diagnosis (10-20): with no thinking budget the IaC persona thought 10k-28k tokens (avg ~21k) to
    # write a 0.3k-1k token intent, ~40 % of a run's real spend; its calls also reserved the 65 536-token developer
    # ceiling. Intent mode only: the IaC junior call gets this thinking budget and output bound (thinking counts
    # inside max_output_tokens on Vertex). The other juniors and every mode-off call are unchanged.
    iac_intent_thinking_budget: int = Field(default=4096, ge=128, le=32_768,
                                            description="intent mode only: thinking tokens of the IaC junior call")
    iac_intent_max_output_tokens: int = Field(default=16_384, ge=2048, le=65_536,
                                              description="intent mode only: max_output_tokens of the IaC junior "
                                                          "call (candidates + thoughts)")

    @field_validator("repair_model")
    @classmethod
    def _known_repair_model(cls, v: str) -> str:
        return validate_model_id(v, "repair_model")   # UNSUPPORTED_MODEL_CONFIG at settings time, never at a call

    @model_validator(mode="after")
    def _thinking_leaves_room_for_the_answer(self) -> "HallucinationStackSettings":
        if self.repair_thinking_budget + MIN_REPAIR_CANDIDATE_TOKENS > self.repair_max_output_tokens:
            raise ValueError("repair_thinking_budget + 1024 must be <= repair_max_output_tokens (the thinking budget "
                             "is part of the per-call bound)")
        if self.iac_intent_thinking_budget + MIN_REPAIR_CANDIDATE_TOKENS > self.iac_intent_max_output_tokens:
            raise ValueError("iac_intent_thinking_budget + 1024 must be <= iac_intent_max_output_tokens")
        return self


def effective_repair_token_budget(settings: HallucinationStackSettings,
                                  max_swarm_token_envelope: Optional[int] = None) -> int:
    envelope = max_swarm_token_envelope or DEFAULT_SWARM_TOKEN_ENVELOPE
    return min(settings.repair_token_budget, int(round(settings.repair_budget_envelope_fraction * envelope)))


def effective_dispatch_token_budget(settings: HallucinationStackSettings,
                                    max_swarm_token_envelope: Optional[int] = None) -> int:
    """QA-REPAIR-BUDGET: the token budget of one developer dispatch (today's per-trace formula and values)."""
    envelope = max_swarm_token_envelope or DEFAULT_SWARM_TOKEN_ENVELOPE
    return min(settings.repair_dispatch_token_budget,
               int(round(settings.repair_dispatch_envelope_fraction * envelope)))


def repair_call_max_output_tokens(settings: HallucinationStackSettings, files_to_fix_tokens: int,
                                  model: Optional[str] = None) -> int:
    """The per-call bound on candidates + thoughts, sent as max_output_tokens:
    min(repair_max_output_tokens, 1.5 x tokens(files_to_fix) + 2048 + repair_thinking_budget).
    The answer keeps the F7 room (1.5 x tokens(files_to_fix) + 2048, one full rewrite of every diagnosed file) on
    top of the explicit thinking budget; when the cap binds the answer gets cap - thinking_budget (>= 1024).
    A thinking-level model (Gemini 4 Argon, no budget) gets the same bound with its LOW-level thinking reserve in
    place of the budget, capped at its non-streaming output cap (gemini_model_config.max_output_tokens_for); any
    other model (and model=None) gets the bound above unchanged."""
    answer = 1.5 * max(0, files_to_fix_tokens) + 2048
    bound = int(min(settings.repair_max_output_tokens, answer + settings.repair_thinking_budget))
    if model is None:
        return bound
    return int(max_output_tokens_for(model, bound, Purpose.REPAIR,
                                     reserved_thinking_tokens=settings.repair_thinking_budget))


def repair_call_thinking_budget(settings: HallucinationStackSettings,
                                model: Optional[str] = None) -> Optional[int]:
    """ThinkingConfig(thinking_budget=...) of every repair call; always < repair_call_max_output_tokens(...).
    None for a thinking-level model (Gemini 4 Argon): it takes no budget (its LOW level is set by the request rules)
    and its call bound already replaced the budget with the level reserve, so no Flash budget rides on its task
    (Argon RT F2). Any other model (and model=None) gets the budget unchanged."""
    if model is not None:
        fam = resolve_model_family(model)
        if fam is not None and fam.thinking is ThinkingControl.LEVEL:
            return None
    return int(settings.repair_thinking_budget)


def resolve_repair_model(settings: HallucinationStackSettings, developer_model: str) -> str:
    return settings.repair_model or developer_model
