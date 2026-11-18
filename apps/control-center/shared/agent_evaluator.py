"""
Project Castor: Agent Quality Evaluator & Prompt Streamliner
Uses the dynamically configured Admin Gemini model (default: the settings' default primary model, gemini-4-carbon,
DEFAULT-MODEL-GEMINI-4-CARBON) to evaluate agent executions against their system instructions and streamline prompts.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("agent-evaluator")


def _model_config() -> Any:
    """The vendored model-family module (shared/gemini_model_config.py), or None when it cannot be imported."""
    try:
        try:
            from shared import gemini_model_config as gmc
        except ImportError:  # pragma: no cover - vendored as a relative package
            from . import gemini_model_config as gmc  # type: ignore
        return gmc
    except Exception as e:  # noqa: BLE001
        logger.error(f"model family rules unavailable ({type(e).__name__}: {e})")
        return None


# DEFAULT-MODEL-GEMINI-4-CARBON (owner 11-11): the code default primary model, the one the settings use.
DEFAULT_EVALUATION_MODEL = getattr(_model_config(), "DEFAULT_PRIMARY_MODEL", None) or "gemini-4-carbon"


def get_evaluation_model(db_client: Any = None) -> str:
    """
    Resolves the evaluation model dynamically from Firestore platform_settings.
    Defaults to DEFAULT_EVALUATION_MODEL (the settings' default primary model) if not explicitly configured.
    """
    default_model = DEFAULT_EVALUATION_MODEL
    if not db_client:
        try:
            from google.cloud import firestore
            project_id = os.getenv("PROJECT_ID", "")
            if project_id:
                db_client = firestore.Client(project=project_id)
        except Exception:
            pass

    if db_client:
        try:
            doc = db_client.collection("system_config").document("platform_settings").get()
            if doc.exists:
                data = doc.to_dict() or {}
                models_cfg = data.get("models") or {}
                eval_model = models_cfg.get("architect_model") or models_cfg.get("developer_model")
                if eval_model and isinstance(eval_model, str):
                    return eval_model
        except Exception as e:
            logger.debug(f"Could not load evaluation model from platform_settings: {e}")

    return default_model


def _family_request_kwargs(model_name: str, types: Any) -> Dict[str, Any]:
    """JUDGE-LEVEL-FAMILY-CONFIG (owner 11-11): {"config": ...} by the model family's rules for an "auxiliary" call,
    or {} when the family adds nothing. A Gemini <= 3.x model (or an id with no family) gets {}: its request stays
    exactly `generate_content(model=..., contents=...)`. A level-family model (Gemini 4 Argon / Carbon, a stored LEVEL
    style) gets ThinkingConfig(thinking_level=<the auxiliary level, models.thinking_levels>) and no budget."""
    try:
        try:
            from shared.gemini_model_config import Purpose, adapt_generate_config_kwargs
        except ImportError:  # pragma: no cover - vendored as a relative package
            from .gemini_model_config import Purpose, adapt_generate_config_kwargs  # type: ignore
    except Exception as e:  # noqa: BLE001 - no family rules here: the request is sent as before this change
        logger.error(f"model family rules unavailable for '{model_name}' ({type(e).__name__}: {e}); request sent "
                     "without a config")
        return {}
    kwargs = adapt_generate_config_kwargs(model_name, Purpose.AUXILIARY, {}, types=types)
    return {"config": types.GenerateContentConfig(**kwargs)} if kwargs else {}


def _call_gemini_inference(prompt_text: str, model_name: str) -> Optional[str]:
    """
    Invokes Gemini API via google-genai or vertexai, with fallback.
    """
    # 1. Try google-genai SDK
    try:
        from google import genai
        from google.genai import types
        client = genai.Client()
        response = client.models.generate_content(
            model=model_name,
            contents=prompt_text,
            **_family_request_kwargs(model_name, types),
        )
        if response and response.text:
            return response.text
    except Exception as e:
        logger.debug(f"google-genai evaluation inference error with {model_name}: {e}")

    # 2. Try vertexai SDK fallback
    try:
        import vertexai
        from vertexai.generative_models import GenerativeModel
        project_id = os.getenv("PROJECT_ID", "")
        if project_id:
            # DEFAULT-MODEL-GEMINI-4-CARBON: a region that does not serve the model's family (Gemini 4 Argon /
            # Carbon) is replaced by the global endpoint (typed rule, gemini_model_config.vertex_location_for).
            location = os.getenv("DEFAULT_GCP_REGION", "us-central1")
            gmc = _model_config()
            if gmc is not None:
                location = gmc.vertex_location_for(model_name, location)
            vertexai.init(project=project_id, location=location)
            model = GenerativeModel(model_name)
            resp = model.generate_content(prompt_text)
            if resp and resp.text:
                return resp.text
    except Exception as e2:
        logger.debug(f"vertexai evaluation inference error with {model_name}: {e2}")

    return None


def evaluate_agent_execution(
    stage_name: str,
    rendered_prompt: str,
    agent_output: str,
    context_metadata: Optional[Dict[str, Any]] = None,
    db_client: Any = None,
) -> Dict[str, Any]:
    """
    Evaluates an agent's output against its rendered system prompt.
    Returns a structured dictionary matching AgentEvalMetric.
    """
    model_name = get_evaluation_model(db_client)
    now_iso = datetime.now(timezone.utc).isoformat()

    context_section = ""
    if context_metadata:
        context_section = f"""
### 3. SUBAGENT TASK BREAKDOWN & FILE ATTRIBUTION CONTEXT:
```json
{json.dumps(context_metadata, indent=2)[:3000]}
```
"""

    eval_rubric_prompt = f"""You are the StackVend Agent Quality Auditor.
Audit the following autonomous agent execution. The agent executed stage: '{stage_name}'.

### 1. RENDERED SYSTEM PROMPT & CONSTRAINTS GIVEN TO AGENT:
```
{rendered_prompt[:6000]}
```

### 2. ACTUAL AGENT OUTPUT:
```
{agent_output[:8000]}
```{context_section}

### AUDIT INSTRUCTIONS & RUBRIC:
Evaluate the output strictly against the instructions provided to the agent:
1. **Instruction & Negative Constraint Adherence (0.0 to 1.0)**: Did the agent follow all mandatory rules, schema requirements, and avoid prohibited actions? (e.g. no unauthorized public IPs, proper deletion_protection, correct module usage).
2. **Technical Grounding (0.0 to 1.0)**: Are all GCP APIs, resource configurations, and syntax valid without hallucinations?
3. **Tool & Synthesis Efficiency (0.0 to 1.0)**: Is the output concise, correct, and directly addressing the goal without bloated or unnecessary code?

You MUST respond strictly with a single valid JSON object in this exact schema:
{{
  "instruction_adherence_score": 0.95,
  "grounding_score": 1.0,
  "tool_efficiency_score": 0.90,
  "eval_summary": "Brief 1-2 sentence assessment",
  "constraint_violations": ["Any specific rules violated or empty list if none"],
  "attributed_violations": [
    {{
      "persona": "BACKEND_ENGINEER",
      "file_path": "path/to/file",
      "violation": "Detailed description of violation",
      "severity": "WARNING"
    }}
  ]
}}
Do not include any surrounding markdown fences or text outside the JSON object.
"""

    raw_resp = _call_gemini_inference(eval_rubric_prompt, model_name)
    if raw_resp:
        try:
            clean_json = raw_resp.strip()
            if clean_json.startswith("```json"):
                clean_json = clean_json[7:]
            if clean_json.startswith("```"):
                clean_json = clean_json[3:]
            if clean_json.endswith("```"):
                clean_json = clean_json[:-3]
            clean_json = clean_json.strip()

            parsed = json.loads(clean_json)
            return {
                "instruction_adherence_score": float(parsed.get("instruction_adherence_score", 1.0)),
                "grounding_score": float(parsed.get("grounding_score", 1.0)),
                "tool_efficiency_score": float(parsed.get("tool_efficiency_score", 1.0)),
                "eval_judge_model": model_name,
                "eval_summary": str(parsed.get("eval_summary", "Autonomous evaluation completed.")),
                "constraint_violations": list(parsed.get("constraint_violations", [])),
                "attributed_violations": list(parsed.get("attributed_violations", [])),
                "evaluated_at": now_iso,
            }
        except Exception as parse_err:
            logger.warning(f"Error parsing Gemini evaluation response: {parse_err}. Content was: {raw_resp[:200]}")

    # Deterministic Fallback: Rule-based heuristic scoring
    violations = []
    adherence = 1.0
    grounding = 1.0

    # Heuristic 1: Check for public IP if forbidden
    if "no public ip" in rendered_prompt.lower() or "private only" in rendered_prompt.lower():
        if "0.0.0.0/0" in agent_output or "allUsers" in agent_output:
            violations.append("Exposed public ingress when private network required.")
            adherence -= 0.3

    # Heuristic 2: Valid JSON/HCL check
    if rendered_prompt.strip().endswith("JSON object"):
        try:
            json.loads(agent_output.strip())
        except Exception:
            violations.append("Output did not conform to valid JSON format.")
            adherence -= 0.25

    # Heuristic 3: Zero-Dockerfiles Mandate check
    if "dockerfile" in agent_output.lower() and ("dockerfile" in rendered_prompt.lower() or "buildpack" in rendered_prompt.lower()):
        violations.append("Forbidden Dockerfile created in violation of Zero-Dockerfiles Mandate.")
        adherence -= 0.5

    attributed_viols = []
    for v in violations:
        is_docker = "Dockerfile" in v
        attributed_viols.append({
            "rule_or_directive": "Zero-Dockerfile Mandate" if is_docker else "Platform Constraint",
            "violation_message": v,
            "persona": "DEVOPS_ENGINEER" if is_docker else None,
            "file_path": "Dockerfile" if is_docker else None,
        })

    return {
        "instruction_adherence_score": max(0.0, adherence),
        "grounding_score": max(0.0, grounding),
        "tool_efficiency_score": 1.0,
        "eval_judge_model": f"{model_name}-heuristic-fallback",
        "eval_summary": "Evaluated via deterministic heuristic checks.",
        "constraint_violations": violations,
        "attributed_violations": attributed_viols,
        "evaluated_at": now_iso,
    }


def streamline_agent_prompt(
    agent_role: str,
    base_prompt: str,
    directives: List[str],
    db_client: Any = None,
) -> Tuple[str, str]:
    """
    Invokes Gemini to consolidate ad-hoc directives into a clean, unified system prompt.
    Returns (streamlined_prompt_text, diff_summary).
    """
    model_name = get_evaluation_model(db_client)

    prompt_refactor_query = f"""You are the StackVend Chief Prompt Engineer.
We have an agent ({agent_role}) whose system prompt has accumulated several operational directives over time.
Refactor and merge these directives directly into the base system prompt instructions.

### BASE SYSTEM PROMPT:
```
{base_prompt}
```

### ACCUMULATED DIRECTIVES TO CONSOLIDATE:
{json.dumps(directives, indent=2)}

### INSTRUCTIONS:
1. Merge the directives seamlessly into the relevant sections of the base prompt.
2. Remove any redundancies, duplicate instructions, or contradictory phrases.
3. Keep the prompt concise, authoritative, and structured.
4. Preserve all existing schema requirements, JSON formats, and API references.

Respond strictly with a JSON object in this format:
{{
  "streamlined_prompt": "The complete refined system prompt...",
  "diff_summary": "1-2 sentence description of changes made"
}}
"""

    raw_resp = _call_gemini_inference(prompt_refactor_query, model_name)
    if raw_resp:
        try:
            clean_json = raw_resp.strip()
            if clean_json.startswith("```json"):
                clean_json = clean_json[7:]
            if clean_json.startswith("```"):
                clean_json = clean_json[3:]
            if clean_json.endswith("```"):
                clean_json = clean_json[:-3]
            clean_json = clean_json.strip()

            parsed = json.loads(clean_json)
            return (
                str(parsed.get("streamlined_prompt", base_prompt)),
                str(parsed.get("diff_summary", "Consolidated active directives into core instructions.")),
            )
        except Exception as e:
            logger.warning(f"Error parsing prompt streamliner response: {e}")

    # Fallback: append directives cleanly
    fallback_prompt = base_prompt.rstrip() + "\n\n### OPERATIONAL DIRECTIVES:\n" + "\n".join(f"- {d}" for d in directives)
    return fallback_prompt, "Directives appended as operational section (fallback consolidation)."
