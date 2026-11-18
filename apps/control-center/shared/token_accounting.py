"""
Project Castor: Centralized Token Accounting & FinOps Metering
Tracks prompt, candidate, and total token usage across all agents,
computes model-grounded dollar costs, and provides atomic Firestore persistence.
"""

from datetime import date, datetime, timezone
import logging
from typing import Any, Dict, Optional, Tuple
from pydantic import BaseModel, Field

logger = logging.getLogger("castor-token-accounting")

try:  # the model-id rule shared with the family table (Argon RT F4)
    from shared.gemini_model_config import known_model_id
except ImportError:  # pragma: no cover
    from .gemini_model_config import known_model_id  # type: ignore

# Model Pricing Table per 1,000,000 tokens (USD)
# Source: Official Google Gemini Developer API Pricing
MODEL_PRICING: Dict[str, Dict[str, float]] = {
    "gemini-3.8-flash": {"prompt_per_m": 0.075, "candidates_per_m": 0.30},
    "gemini-3.7-flash": {"prompt_per_m": 0.075, "candidates_per_m": 0.30},
    "gemini-2.0-flash": {"prompt_per_m": 0.10, "candidates_per_m": 0.40},
    "gemini-2.0-flash-lite": {"prompt_per_m": 0.075, "candidates_per_m": 0.30},
    "gemini-1.5-flash": {"prompt_per_m": 0.075, "candidates_per_m": 0.30},
    "gemini-1.5-pro": {"prompt_per_m": 1.25, "candidates_per_m": 5.00},
    # Gemini 4 Argon (owner 10-14), INTRODUCTORY price to 2026-11-30; from 2026-12-01 MODEL_PRICE_CHANGES applies.
    # Third-party source, NOT owner-verified: confirm against the Vertex AI pricing page.
    "gemini-4-argon": {"prompt_per_m": 2.00, "candidates_per_m": 10.00, "cached_prompt_per_m": 0.10},
    # Gemini 4 Carbon (owner 11-10, GEMINI-4-CARBON): Vertex AI list price, global online, from the Cloud Billing
    # Catalog (effective 2026-11-10). A launch discount, if any, is applied by Google as credits and is not shown here.
    "gemini-4-carbon": {"prompt_per_m": 4.00, "candidates_per_m": 20.00, "cached_prompt_per_m": 0.20},
    "default": {"prompt_per_m": 0.075, "candidates_per_m": 0.30},
}

# Dated price changes: model -> ((first UTC date the row applies, row), ...) in ascending date order. On or after a
# date (exact date compare) that row replaces the MODEL_PRICING row; before the first date MODEL_PRICING applies.
MODEL_PRICE_CHANGES: Dict[str, Tuple[Tuple[date, Dict[str, float]], ...]] = {
    "gemini-4-argon": (
        (date(2026, 12, 1), {"prompt_per_m": 4.00, "candidates_per_m": 20.00, "cached_prompt_per_m": 0.20}),
    ),
}


UNKNOWN_MODEL_PRICE = "UNKNOWN_MODEL_PRICE"


class UnknownModelPrice(LookupError):
    """OPEN-MODEL-SETTINGS (owner 11-10): a model with no built-in rules and no price row has no known price. Its cost
    is reported as unknown, never as $0 and never at another model's price."""
    code = UNKNOWN_MODEL_PRICE

    def __init__(self, model: str):
        super().__init__(f"{UNKNOWN_MODEL_PRICE}: model {model!r} has no price row")
        self.model = model


_warned_unpriced: set = set()


def model_pricing(model_name: str, on: Optional[date] = None) -> Dict[str, float]:
    """The price row of `model_name` on UTC date `on` (default: today, UTC). The id is resolved with the model-family
    rule (gemini_model_config.known_model_id: path prefix stripped, `<known id>-<suffix>` -> the known id), so an id
    settings accept is priced as its family (Argon RT F4). A built-in model without its own row keeps the "default"
    row (as before); any other id without a row (a model entered in Settings, OPEN-MODEL-SETTINGS) raises
    UnknownModelPrice."""
    clean_model = (model_name or "gemini-3.8-flash").lower().strip()
    known = known_model_id(clean_model)
    if known is not None and known in MODEL_PRICING:
        clean_model = known
    if known is None and clean_model not in MODEL_PRICING:
        raise UnknownModelPrice(model_name)
    row = MODEL_PRICING.get(clean_model, MODEL_PRICING["default"])
    day = on or datetime.now(timezone.utc).date()
    for starts, changed in MODEL_PRICE_CHANGES.get(clean_model, ()):
        if day >= starts:
            row = changed
    return row


class AgentTokenRecord(BaseModel):
    prompt_tokens: int = 0
    candidates_tokens: int = 0
    total_tokens: int = 0
    cost_usd: Optional[float] = 0.0          # None = unknown price (UNKNOWN_MODEL_PRICE), never shown as $0
    cost_status: str = "PRICED"              # PRICED | UNKNOWN_MODEL_PRICE
    model: str = "gemini-3.8-flash"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "SUCCESS"  # SUCCESS | TRUNCATED_OR_RETRY


class ExecutionTokenSummary(BaseModel):
    total_prompt_tokens: int = 0
    total_candidates_tokens: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    by_agent: Dict[str, Any] = Field(default_factory=dict)


def calculate_token_cost(model_name: str, prompt_tokens: int, candidates_tokens: int,
                         on: Optional[date] = None) -> Optional[float]:
    """Calculates estimated USD cost for token consumption using official model pricing (on UTC date `on`,
    default today; see MODEL_PRICE_CHANGES). None when the model's price is unknown (UnknownModelPrice)."""
    try:
        pricing = model_pricing(model_name, on)
    except UnknownModelPrice:
        key = (model_name or "").lower().strip()
        if key not in _warned_unpriced:
            _warned_unpriced.add(key)
            logger.warning(f"{UNKNOWN_MODEL_PRICE}: model '{model_name}' has no price row; its cost is reported as "
                           "unknown")
        return None

    prompt_cost = (prompt_tokens / 1_000_000.0) * pricing["prompt_per_m"]
    candidates_cost = (candidates_tokens / 1_000_000.0) * pricing["candidates_per_m"]
    return round(prompt_cost + candidates_cost, 6)


def extract_token_usage(
    response: Any,
    model_name: str = "gemini-3.8-flash",
    status: str = "SUCCESS",
) -> Optional[AgentTokenRecord]:
    """
    Safely extracts token usage metrics from a Google GenAI GenerateContentResponse
    or candidates payload.
    """
    if not response:
        return None

    prompt_tokens = 0
    candidates_tokens = 0
    total_tokens = 0

    try:
        # Check standard google.genai response.usage_metadata
        usage = getattr(response, "usage_metadata", None)
        if usage:
            prompt_tokens = getattr(usage, "prompt_token_count", 0) or 0
            candidates_tokens = getattr(usage, "candidates_token_count", 0) or 0
            total_tokens = getattr(usage, "total_token_count", 0) or (prompt_tokens + candidates_tokens)
        elif isinstance(response, dict):
            u_dict = response.get("usage_metadata") or response.get("usageMetadata") or {}
            prompt_tokens = u_dict.get("prompt_token_count") or u_dict.get("promptTokenCount") or 0
            candidates_tokens = u_dict.get("candidates_token_count") or u_dict.get("candidatesTokenCount") or 0
            total_tokens = u_dict.get("total_token_count") or u_dict.get("totalTokenCount") or (prompt_tokens + candidates_tokens)

        # Fallback calculation if total_tokens is 0 but prompt or candidates were populated
        if total_tokens == 0 and (prompt_tokens > 0 or candidates_tokens > 0):
            total_tokens = prompt_tokens + candidates_tokens

        cost_usd = calculate_token_cost(model_name, prompt_tokens, candidates_tokens)

        return AgentTokenRecord(
            prompt_tokens=prompt_tokens,
            candidates_tokens=candidates_tokens,
            total_tokens=total_tokens,
            cost_usd=cost_usd,
            cost_status="PRICED" if cost_usd is not None else UNKNOWN_MODEL_PRICE,
            model=model_name,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status=status,
        )
    except Exception as e:
        logger.debug(f"Failed to extract token usage: {e}")
        return None


def record_agent_tokens(
    db: Any,
    trace_id: str,
    stage_name: str,
    usage: Optional[AgentTokenRecord],
) -> None:
    """
    Atomically records agent token usage into Firestore pipeline_executions/{trace_id}.
    Uses firestore.Increment to prevent race conditions during concurrent swarm writes.
    """
    if not db or not trace_id or not usage or usage.total_tokens <= 0:
        return False

    try:
        from google.cloud import firestore

        clean_stage = stage_name.lower().replace("-", "_")
        doc_ref = db.collection("pipeline_executions").document(trace_id)

        update_payload = {
            "token_usage.total_prompt_tokens": firestore.Increment(usage.prompt_tokens),
            "token_usage.total_candidates_tokens": firestore.Increment(usage.candidates_tokens),
            "token_usage.total_tokens": firestore.Increment(usage.total_tokens),
            f"token_usage.by_agent.{clean_stage}.prompt_tokens": firestore.Increment(usage.prompt_tokens),
            f"token_usage.by_agent.{clean_stage}.candidates_tokens": firestore.Increment(usage.candidates_tokens),
            f"token_usage.by_agent.{clean_stage}.total_tokens": firestore.Increment(usage.total_tokens),
            f"token_usage.by_agent.{clean_stage}.model": usage.model,
            f"token_usage.by_agent.{clean_stage}.last_updated": usage.timestamp,
        }
        if usage.cost_usd is not None:
            update_payload["token_usage.total_cost_usd"] = firestore.Increment(usage.cost_usd)
            update_payload[f"token_usage.by_agent.{clean_stage}.cost_usd"] = firestore.Increment(usage.cost_usd)
        else:   # OPEN-MODEL-SETTINGS: an unknown price is recorded as unknown, never added as $0
            update_payload["token_usage.unpriced_models"] = firestore.ArrayUnion([usage.model])
            update_payload[f"token_usage.by_agent.{clean_stage}.cost_status"] = UNKNOWN_MODEL_PRICE

        # Try update first (requires doc to exist); if doc does not exist, use set with merge
        try:
            doc_ref.update(update_payload)
        except Exception:
            # Fallback for new documents: set with merge
            doc_ref.set(update_payload, merge=True)

        cost_text = f"${usage.cost_usd:.5f}" if usage.cost_usd is not None else "cost unknown"
        logger.debug(
            f"Recorded {usage.total_tokens} tokens ({cost_text}) for stage '{clean_stage}' in trace '{trace_id}'"
        )
        return True
    except Exception as e:
        logger.debug(f"Notice: Failed to record agent tokens in Firestore for {trace_id}: {e}")
        return False


def rollup_tokens_to_feature(
    db: Any,
    trace_id: str,
    request_id: Optional[str] = None,
    product_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Rolls up aggregated token usage from pipeline_executions/{trace_id}
    into feature_requests/{request_id} and workloads/{product_id}.
    """
    if not db or not trace_id:
        return None

    try:
        from google.cloud import firestore

        doc_ref = db.collection("pipeline_executions").document(trace_id)
        doc = doc_ref.get()
        if not doc.exists:
            return None

        d_dict = doc.to_dict() or {}
        token_usage = d_dict.get("token_usage")
        if not token_usage or not isinstance(token_usage, dict):
            return None

        # Clean cost precision for serialization
        total_tokens = token_usage.get("total_tokens", 0)
        total_cost = round(float(token_usage.get("total_cost_usd", 0.0)), 6)
        token_usage["total_cost_usd"] = total_cost

        # Ensure both 'by_agent' and 'agents' are available for UI compatibility
        if "by_agent" in token_usage and "agents" not in token_usage:
            token_usage["agents"] = token_usage["by_agent"]
        elif "agents" in token_usage and "by_agent" not in token_usage:
            token_usage["by_agent"] = token_usage["agents"]

        # 1. Roll up to feature_requests if request_id is known or resolvable
        target_req_id = request_id or d_dict.get("request_id")
        if target_req_id:
            db.collection("feature_requests").document(target_req_id).set({
                "token_usage": token_usage,
                "total_tokens": total_tokens,
                "total_cost_usd": total_cost,
                # OPEN-MODEL-SETTINGS: total_cost_usd covers only the priced models when this is non-empty
                "unpriced_models": list(token_usage.get("unpriced_models") or []),
            }, merge=True)
            logger.info(f"Rolled up token usage ({total_tokens:,} tokens, ${total_cost:.4f}) to feature_request '{target_req_id}'")

        # 2. Roll up to workloads/{product_id}.cumulative_token_usage
        target_prod_id = product_id or d_dict.get("product_id")
        if target_prod_id:
            try:
                db.collection("workloads").document(target_prod_id).set({
                    "cumulative_token_usage.total_prompt_tokens": firestore.Increment(token_usage.get("total_prompt_tokens", 0)),
                    "cumulative_token_usage.total_candidates_tokens": firestore.Increment(token_usage.get("total_candidates_tokens", 0)),
                    "cumulative_token_usage.total_tokens": firestore.Increment(total_tokens),
                    "cumulative_token_usage.total_cost_usd": firestore.Increment(total_cost),
                    "cumulative_token_usage.last_updated": datetime.now(timezone.utc).isoformat(),
                    **({"cumulative_token_usage.unpriced_models": firestore.ArrayUnion(
                        list(token_usage["unpriced_models"]))} if token_usage.get("unpriced_models") else {}),
                }, merge=True)
                logger.info(f"Incremented cumulative workload tokens for '{target_prod_id}' (+{total_tokens:,} tokens)")
            except Exception as w_err:
                logger.debug(f"Workload cumulative tokens notice: {w_err}")

        return token_usage
    except Exception as e:
        logger.debug(f"Failed to rollup tokens to feature/workload for {trace_id}: {e}")
        return None
