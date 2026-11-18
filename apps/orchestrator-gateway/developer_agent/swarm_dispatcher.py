"""
Project Castor: Hardened Phased Multi-Wave Swarm Dispatcher
Coordinates concurrent junior developer workers in sequential waves with rate-limiting,
surgical dependency injection, disjoint file staging, bounded self-healing, and FinOps circuit breakers.
"""

import asyncio
import contextvars
import json
import logging
import random
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from google.cloud import firestore

try:
    from shared.settings import get_model_cascade_for_agent
    from shared.cooldown_manager import is_rate_limit_error, is_transient_vertex_error
except ImportError:
    try:
        from ..shared.settings import get_model_cascade_for_agent
        from ..shared.cooldown_manager import is_rate_limit_error, is_transient_vertex_error
    except ImportError:
        def get_model_cascade_for_agent(agent_name, project_id=None):
            return ["gemini-4-carbon", "gemini-4-argon"]
        def is_rate_limit_error(e):
            return "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e).upper()
        def is_transient_vertex_error(e):
            if e is None:
                return False
            err_str = str(e).lower()
            return any(k in err_str for k in ["429", "500", "502", "503", "504", "harpoon", "resource_exhausted", "internal error", "unavailable"])

try:
    from shared.diagnostics import Diagnostic, ErrorClass, StageError, ValidationReport
except ImportError:  # pragma: no cover
    from ..shared.diagnostics import Diagnostic, ErrorClass, StageError, ValidationReport  # type: ignore

try:  # Argon compat (owner 10-14): per-model-family request rules; identity for Gemini <= 3.x
    from shared.gemini_model_config import (Purpose, adapt_generate_config_kwargs, max_output_tokens_for,
                                            thinking_config_for)
except ImportError:  # pragma: no cover
    from ..shared.gemini_model_config import (Purpose, adapt_generate_config_kwargs,  # type: ignore
                                              max_output_tokens_for, thinking_config_for)

try:
    from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_random_exponential
except ImportError:
    # Graceful fallback if tenacity is not installed in lightweight test environments
    def retry(*args, **kwargs):
        def decorator(f):
            return f
        return decorator
    def retry_if_exception_type(*args, **kwargs):
        return None
    def stop_after_attempt(*args, **kwargs):
        return None
    def wait_random_exponential(*args, **kwargs):
        return None

from .errors import LLM_UNAVAILABLE, DeveloperStageError
import stage_deadline   # STAGE-DEADLINE (gateway root module)
from .juniors.prompt_registry import resolve_junior_prompt
from .prompt import with_app_auth_rule
from .contract_registry import rerender_service_inits   # SCHEMAS-COLLISION
from .iac_intent_contract import intent_response_json_schema, normalize_intent_envelope   # TI-3

# Repair-call transport retry (R3c, 10-13): provider statuses that are transient, and the backoff before each retry.
# QA-JUDGE-RETRY (10-27): the rule lives in llm_transport, shared with the QA Stage 2 judge; same values.
from .llm_transport import RETRY_BACKOFF_S as REPAIR_RETRY_BACKOFF_S  # noqa: F401  (R3c name, kept; the walk uses it)
from .llm_transport import TRANSIENT_PROVIDER_STATUS as REPAIR_TRANSIENT_STATUS  # noqa: F401  (R3c name, kept)
from .llm_transport import transient_status  # noqa: F401  (the typed rule; the walk classifies with it)
# SLOW-CALL-FALLBACK (owner 11-13): the per-call timeout and fallback walk of every model call made here
from .llm_transport import (DEFAULT_CALL_TIMEOUTS, NO_STAGE_BUDGET, REPAIR_WALL_CLOCK, CallPurpose, CallWalk,
                            LlmFallbackExhausted, active_stage_bound, LlmStageBudgetExhausted, ledger_abandoned_sink)
from .swarm_schemas import (
    ConflictingFileAssignmentError,
    ContractAmendment,
    FinOpsCircuitBreakerError,
    JuniorExecutionResult,
    JuniorFilesEnvelope,
    JuniorPersona,
    JuniorTaskAssignment,
    LeadDeveloperDecompositionPlan,
    PoisonedContractEscalationError,
    UnauthorizedFileCreationError,
)

logger = logging.getLogger("castor-swarm-dispatcher")

# SCHEMAS-COLLISION (owner 10-28): where shared models live, stated in the platform-owned anchor of every junior task
# of a plan with Wave 0 contract files (contract_registry: the `schemas/` package and its re-export render).
WAVE0_SCHEMAS_RULE = (
    "Shared models: in every service, `schemas/` is a platform package. `schemas/contracts.py` holds the Wave 0 "
    "contracts and `schemas/__init__.py` re-exports it and every `schemas/<name>.py` module this plan assigns, so "
    "import shared models as `from schemas import Name`. Inside `schemas/<name>.py`, import a contract as "
    "`from .contracts import Name` and a sibling module's model as `from .<other> import Name`. "
    "There is no `schemas.py` module.\n"
)


def stage_junior_files(
    staged_tree: Dict[str, str],
    task: JuniorTaskAssignment,
    incoming_files: Dict[str, str],
) -> None:
    """
    Enforces Disjoint File Partition Invariant & Unauthorized File Creation Protection.
    Guarantees no two tasks silently clobber each other's files.
    """
    for filepath, content in incoming_files.items():
        # Check 1: File Collision Detection
        if filepath in staged_tree:
            raise ConflictingFileAssignmentError(
                f"File collision detected on '{filepath}'. Task '{task.task_id}' ({task.persona}) "
                f"attempted to overwrite an existing staged file. Partitions must be strictly disjoint."
            )
        # Check 2: Unauthorized Scope Detection
        if filepath not in task.assigned_files:
            raise UnauthorizedFileCreationError(
                f"Task '{task.task_id}' ({task.persona}) attempted to stage undeclared file '{filepath}'. "
                f"Assigned scope is strictly: {task.assigned_files}"
            )
        staged_tree[filepath] = content


class JuniorEnvelopeInvalid(Exception):
    """V6 (S2-A A1, register HS-61): a junior response that is not valid JSON. Carries the parser's own message (with
    line/column) so the retry is a typed re-ask instead of the same prompt sent again."""

    def __init__(self, error: str):
        self.error = error
        super().__init__(error)


JSON_OUTPUT_TRUNCATED = "JSON.OUTPUT_TRUNCATED"


class JuniorOutputTruncated(Exception):
    """TI5-TRUNC (owner 10-25): the IaC-intent junior's answer stopped at the output token cap, as the API's own finish
    reason says (FinishReason.MAX_TOKENS), detected before any JSON parse. Carries the cap actually sent and, when the
    response has them, the thinking / answer token counts (Vertex counts both inside max_output_tokens)."""

    code = JSON_OUTPUT_TRUNCATED

    def __init__(self, cap: int, developer_limit: int, thoughts: Optional[int] = None, answer: Optional[int] = None):
        self.cap, self.developer_limit, self.thoughts, self.answer = int(cap), int(developer_limit), thoughts, answer
        super().__init__(f"{JSON_OUTPUT_TRUNCATED}: the answer stopped at the output token cap {self.cap} (finish "
                         f"reason MAX_TOKENS; thinking tokens {thoughts}, answer tokens {answer})")


# TI5-TRUNC: the one re-ask after a truncated IaC-intent answer names the actual failure (never the JSON-escape note).
TRUNCATION_REASK = ("\n\nERROR JSON.OUTPUT_TRUNCATED: the previous attempt ran out of output tokens before it finished "
                    "the JSON object (finish reason MAX_TOKENS), so nothing of it could be used. Answer with the "
                    "complete JSON object these instructions ask for, and nothing else.")


# SLOW-CALL-FALLBACK: the junior attempt's fallback models (the task's cascade after the chosen model) and the dict the
# call fills with its provenance. A context variable, so concurrent junior tasks never share it and the
# `_call_gemini_with_backoff` signature (stubbed by tests and the eval harness) is unchanged.
_JUNIOR_CALL: contextvars.ContextVar = contextvars.ContextVar("castor_junior_call", default=None)


def _chain_after(model_name: str, cascade: List[str]) -> List[str]:
    """`model_name` then the cascade models after it, no duplicates. `cascade` = [role model] + fallback_models. A
    model outside the cascade (a separately configured repair model) is followed by the fallback models only, never
    by the role's primary: a deliberately cheaper repair model must not fall back "up" to it (RT F7)."""
    rest = cascade[cascade.index(model_name) + 1:] if model_name in cascade else list(cascade[1:])
    out = [model_name]
    for m in rest:
        if m and m not in out:
            out.append(m)
    return out


def _token_count(usage: Any, field_name: str) -> Optional[int]:
    """An int token count of the response's usage_metadata, or None when the response does not carry it."""
    value = getattr(usage, field_name, None) if usage is not None else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def json_output_truncated_error(task_id: str, persona: str, err: "JuniorOutputTruncated", attempts: int,
                                reasked: bool) -> StageError:
    """TI5-TRUNC: typed CODE_DEFECT for an IaC-intent junior whose answer was cut off at the token cap again after
    the one re-ask with the raised cap (`reasked`), or on its last attempt (no attempt left for the re-ask)."""
    why = "after the one truncation re-ask" if reasked else "on its last attempt"
    diag = Diagnostic(tool="schema", code=JSON_OUTPUT_TRUNCATED, severity="error", file=f"<junior:{task_id}>",
                      symbol=str(persona), source="precommit",
                      message=f"junior task {task_id!r} ({persona}) stopped at the output token cap {why} (attempt "
                              f"{attempts}; cap sent {err.cap}; thinking tokens {err.thoughts}, answer tokens "
                              f"{err.answer})")
    report = ValidationReport(status="FAIL", source="precommit", artifact_hash="", diagnostics=[diag],
                              error_class=ErrorClass.CODE_DEFECT)
    return StageError(report, f"{JSON_OUTPUT_TRUNCATED}: junior task {task_id} ({persona}) after {attempts} attempts")


JSON_REASK = ("\n\nERROR JSON.OUTPUT_INVALID: your previous response was not valid JSON ({error}). Resend the same "
              "files as ONE valid JSON object {{\"files\": {{\"<path>\": \"<content>\"}}}}: inside JSON strings escape "
              "every backslash as \\\\ and every newline as \\n; no text outside the JSON object.")
# Single-turn path (HS-12): the next request goes to the next model of the cascade, so the note names the previous
# attempt, not "your" response (code RT F3).
JSON_REASK_PREVIOUS_ATTEMPT = (
    "\n\nERROR JSON.OUTPUT_INVALID: the previous attempt's response was not valid JSON ({error}). Send the files as "
    "ONE valid JSON object {{\"files\": {{\"<path>\": \"<content>\"}}}}: inside JSON strings escape every backslash "
    "as \\\\ and every newline as \\n; no text outside the JSON object.")
# TI-5-G2 (owner 10-24): the single-turn answer parsed, but a file's content is not text (the next attempt is told
# exactly which paths); before, a non-string content crashed the stack with an untyped TypeError.
FILES_REASK_PREVIOUS_ATTEMPT = (
    "\n\nERROR JSON.OUTPUT_INVALID: in the previous attempt's \"files\" object the content of {paths} was not a JSON "
    "string. Every value in \"files\" is ONE JSON string holding the whole file text.")


def json_output_invalid_error(task_id: str, persona: str, error: str, attempts: int) -> StageError:
    """Typed CODE_DEFECT for a junior whose every attempt returned invalid JSON (never a silent drop, HS-61)."""
    diag = Diagnostic(tool="schema", code="JSON.OUTPUT_INVALID", severity="error", file=f"<junior:{task_id}>",
                      symbol=str(persona), source="precommit",
                      message=f"junior task {task_id!r} ({persona}) returned invalid JSON on all {attempts} attempts; "
                              f"last parser error: {error}")
    report = ValidationReport(status="FAIL", source="precommit", artifact_hash="", diagnostics=[diag],
                              error_class=ErrorClass.CODE_DEFECT)
    return StageError(report, f"JSON.OUTPUT_INVALID: junior task {task_id} ({persona}) after {attempts} attempts")


def envelope_check(clean_json: str) -> Dict[str, Any]:
    """V6: JuniorFilesEnvelope.model_validate(json.loads(clean_json)) -> {"ok": bool, "error": str|None}."""
    try:
        JuniorFilesEnvelope.model_validate(json.loads(clean_json))
        return {"ok": True, "error": None}
    except Exception as e:  # noqa: BLE001 - JSONDecodeError / ValidationError: the finding, not a crash
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:300]}"}


# STAGE-TRACE-BY-TASK (owner 11-13): `pipeline_executions/{trace}/stage_traces/developer_task_<task_id>`, one per task.
JUNIOR_TASK_TRACE_PREFIX = "developer_task_"
_PLAIN_TASK_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}")


def junior_task_trace_doc_id(task_id: Any) -> str:
    """The task's stage-trace document id. Task ids are written by the lead model: an id that is not a plain
    [A-Za-z0-9_.-]{1,128} string (or is "." / "..") is keyed by its sha256 instead, so the id is always a valid
    Firestore document id."""
    text = task_id if isinstance(task_id, str) else repr(task_id)
    if _PLAIN_TASK_ID.fullmatch(text) and text not in (".", ".."):
        return JUNIOR_TASK_TRACE_PREFIX + text
    import hashlib
    return JUNIOR_TASK_TRACE_PREFIX + "sha256_" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


class SwarmDispatcher:
    def __init__(
        self,
        genai_client: Optional[Any] = None,
        model_name: str = "gemini-3.7-flash",
        max_concurrency: int = 5,
        db: Optional[firestore.Client] = None,
    ):
        self.genai_client = genai_client
        self.model_name = model_name
        self.max_concurrency = max_concurrency
        self.db = db
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self._state_lock = asyncio.Lock()
        # Lane 19 (27a): True once any junior model call returned a response (LLM_OUTPUT_INVALID vs LLM_UNAVAILABLE).
        self.any_model_answered = False
        self.envelope_checks: List[Dict[str, Any]] = []   # V6 results of every junior response (Step 1 S1-B)
        # every typed JSON re-ask (S2-A A1, code RT F4): {kind, task_id, persona, attempt, model, files, error}; the
        # handler records them as repair_events entries (bounded by the junior's retries, not the repair budget)
        self.junior_reasks: List[Dict[str, Any]] = []
        self._repair_sleep = time.sleep                   # injectable (tests): repair transport backoff
        # SLOW-CALL-FALLBACK (owner 11-13): the stage deadline (absolute time.monotonic(); None = no stage bound, set
        # by the caller), the per-purpose caps, and the injectable clock / async sleep (tests: no real waiting)
        self.deadline: Optional[float] = None
        self.stage_stop: Optional[Callable[[str], BaseException]] = None   # RT F5: the active stage deadline's stop
        self.call_timeouts = DEFAULT_CALL_TIMEOUTS
        self._clock = time.monotonic
        self._async_sleep = None   # None: asyncio.sleep, looked up at each wait
        # who wrote each task's files: {output, task_id, persona, model, primary_model, fallback, fallback_reason}
        self.task_provenance: List[Dict[str, Any]] = []
        # TI-3: the dispatch's iac_intent_contract.IntentRun on the typed-intent path (set by the handler); None = mode
        # "off": every prompt, config and parse below is unchanged
        self.iac_intent: Optional[Any] = None
        # DIRECT-IAP-SKILL-VERIFY: prompt.direct_iap_auth_rule for a PRIVATE_IAP workload (set by the handler); "" =
        # every junior prompt is unchanged
        self.app_auth_rule: str = ""
        # COMMITTED-READ-VIEW (ex04-1114, 11-15): files -> the same files as the platform will commit them (set by the
        # handler: DeveloperAgent._committed_read_view). A junior reads its read_dependencies through it, so a later
        # wave (e.g. the tests) reads exactly the bytes QA will run against, not the draft text the platform rewrites
        # before the commit. The staged tree (the draft) is never changed. None = the dependency texts as staged.
        self.read_view: Optional[Callable[[Dict[str, str]], Dict[str, str]]] = None

    def _emit_telemetry(
        self,
        trace_id: Optional[str],
        product_id: str,
        wave: int,
        total_waves: int,
        task_id: Optional[str] = None,
        status: str = "RUNNING",
        tokens: int = 0,
        error: Optional[str] = None,
    ) -> None:
        """Emits progress heartbeats to Firestore pipeline_executions for Flight Deck DAG updates."""
        if not self.db or not trace_id:
            return
        try:
            update_payload = {
                f"stages.developer.swarm_telemetry.current_wave": wave,
                f"stages.developer.swarm_telemetry.total_waves": total_waves,
                f"stages.developer.swarm_telemetry.updated_at": firestore.SERVER_TIMESTAMP,
            }
            if task_id:
                task_key = f"stages.developer.swarm_telemetry.tasks.{task_id}"
                update_payload[f"{task_key}.status"] = status
                update_payload[f"{task_key}.tokens"] = tokens
                if error:
                    update_payload[f"{task_key}.error"] = error
            self.db.collection("pipeline_executions").document(trace_id).set(update_payload, merge=True)
        except Exception as e:
            logger.debug(f"Could not emit swarm telemetry for {trace_id}: {e}")

    async def invoke_junior_worker(
        self,
        task: JuniorTaskAssignment,
        plan: LeadDeveloperDecompositionPlan,
        dependency_files: Dict[str, str],
        model_name: str,
        trace_id: Optional[str] = None,
    ) -> JuniorExecutionResult:
        """
        Executes a single Junior subagent in its isolated context window.
        Includes bounded self-healing (up to 2 retries) before escalating to the Lead.
        """
        system_instruction = resolve_junior_prompt(task.persona.value, db=self.db)
        intent_task = self.iac_intent is not None and task.persona == JuniorPersona.IAC_ENGINEER
        if intent_task:   # TI-3: the IaC persona fills the typed intent (catalog + slice prompt, this workload's slots)
            system_instruction = self.iac_intent.system_prompt
        system_instruction = with_app_auth_rule(system_instruction, self.app_auth_rule, task.persona)
        arch_anchor = (
            "=== IMMUTABLE ARCHITECTURAL ANCHOR (READ-ONLY GROUNDING) ===\n"
            f"Execution Mode: {plan.execution_mode.value}\n"
            f"IaC Engine: {task.iac_engine}\n"
            f"Lead Notes: {plan.lead_notes}\n"
            "Rule: NEVER invent alternative service routes, ports, or event names not defined in the Shared Contracts.\n"
            "All microservices compile against Wave 0 contracts to guarantee strict inter-service type parity.\n"
            + (WAVE0_SCHEMAS_RULE if getattr(plan, "wave_0_contract_files", None) else "")   # SCHEMAS-COLLISION; none: unchanged
            + "===========================================================\n\n"
        )
        prompt = (
            arch_anchor
            + f"Task ID: {task.task_id}\n"
            f"Persona: {task.persona.value}\n"
            f"Execution Wave: {task.wave}\n"
            f"IaC Engine: {task.iac_engine}\n\n"
            f"Task Objective:\n{task.task_objective}\n\n"
            f"Mandatory Assigned Files (You must ONLY generate these exact files):\n"
            f"{json.dumps(task.assigned_files, indent=2)}\n\n"
            f"Shared Contracts & Schemas:\n{json.dumps(task.injected_contracts or plan.shared_contracts, indent=2)}\n\n"
            f"Specific Guardrails & Rules:\n{json.dumps(task.specific_guardrails, indent=2)}\n\n"
            f"Targeted Dependency Files From Prior Waves (Read-Only Context):\n"
            f"{json.dumps(dependency_files, indent=2)}\n\n"
            f"Generate 100% complete, fully implemented code for your assigned files. "
            f"Respond strictly with a valid JSON object matching: {{\"files\": {{\"filepath\": \"content\"}}}}"
        )
        if intent_task:
            prompt += "\n\n" + self.iac_intent.run_context

        # Determine candidate models for junior worker resilience
        worker_models = [model_name]
        try:
            cascade = get_model_cascade_for_agent("developer")
            for cm in cascade:
                if cm not in worker_models:
                    worker_models.append(cm)
        except Exception:
            pass

        max_retries = 3
        last_error = None
        invalid_json_attempts = 0
        start_time = time.time()
        # Code RT F3: the cascade position advances on every failure EXCEPT invalid JSON, so a typed re-ask goes to
        # the model that produced the parse error; the re-ask note replaces the previous one (never stacked).
        cascade_pos = 0
        body = prompt          # the task prompt plus any omitted-file notes
        reask = ""             # the current JSON re-ask note ("" when the last answer was valid JSON)
        # TI5-TRUNC: the raised IaC-intent output cap once a truncated answer was re-asked (None: the first-attempt
        # cap, IntentRun.max_output_tokens); it stays raised for the task's remaining attempts. Only intent tasks.
        raised_cap: Optional[int] = None
        truncated_attempts = 0

        for attempt in range(max_retries + 1):
            chosen_model = worker_models[min(cascade_pos, len(worker_models) - 1)]
            prompt = body + reask
            call_kwargs: Dict[str, Any] = {"intent_task": True} if intent_task else {}   # TI-3
            if raised_cap is not None:
                call_kwargs["intent_max_output_tokens"] = raised_cap
            # SLOW-CALL-FALLBACK: a too-slow or transient answer walks down this task's cascade after the chosen model
            chosen_pos = worker_models.index(chosen_model)
            call_ctx: Dict[str, Any] = {"fallbacks": tuple(worker_models[chosen_pos + 1:]), "provenance": {}}
            ctx_token = _JUNIOR_CALL.set(call_ctx)
            try:
                try:
                    files, consumed_tokens = await self._call_gemini_with_backoff(
                        prompt, system_instruction, chosen_model, trace_id=trace_id, **call_kwargs)
                finally:
                    _JUNIOR_CALL.reset(ctx_token)
                    answered_by = (call_ctx["provenance"] or {}).get("model")
                    if answered_by in worker_models:
                        # a re-ask (invalid JSON, truncation, omitted files) goes to the model that wrote the answer
                        cascade_pos = worker_models.index(answered_by)
                        chosen_model = answered_by
                prov = call_ctx["provenance"] or {"model": chosen_model, "primary_model": chosen_model,
                                                  "fallback": False, "fallback_reason": None, "attempts": []}
                reask = ""

                # Check that at least one of assigned_files was produced
                missing = [f for f in task.assigned_files if f not in files]
                if missing and attempt < max_retries:
                    logger.warning(f"Task {task.task_id} omitted files {missing} on attempt {attempt + 1}. Retrying...")
                    body += f"\n\nERROR: You omitted the following required files: {missing}. Generate ALL assigned files."
                    cascade_pos += 1
                    continue

                duration = time.time() - start_time
                return JuniorExecutionResult(
                    task_id=task.task_id,
                    persona=task.persona,
                    wave=task.wave,
                    files=files,
                    consumed_tokens=consumed_tokens,
                    duration_seconds=round(duration, 2),
                    status="SUCCEEDED",
                    rendered_prompt=prompt,
                    model=prov.get("model") or chosen_model,
                    model_fallback_reason=prov.get("fallback_reason"),
                    model_attempts=list(prov.get("attempts") or []),
                )
            except JuniorOutputTruncated as e:
                # TI5-TRUNC (owner 10-25): a cut-off IaC-intent answer is re-asked ONCE, to the same model, with the
                # output cap raised to min(developer limit, 2 x intent cap) and a note naming the truncation (not the
                # JSON-escape note). A second truncation, or one with no attempt left, is a typed stop.
                last_error = str(e)
                truncated_attempts += 1
                logger.warning(f"Junior task {task.task_id} answer was cut off at the output token cap on attempt "
                               f"{attempt + 1}/{max_retries + 1} with model '{chosen_model}': {e}")
                if raised_cap is None and attempt < max_retries:
                    raised_cap = min(e.developer_limit, 2 * int(self.iac_intent.max_output_tokens))
                    reask = TRUNCATION_REASK
                    self.junior_reasks.append({
                        "kind": "junior_reask", "task_id": task.task_id, "persona": task.persona.value,
                        "attempt": attempt + 1, "model": chosen_model, "files": list(task.assigned_files),
                        "error": str(e)[:500], "code": JSON_OUTPUT_TRUNCATED, "max_output_tokens": raised_cap})
                    logger.warning(f"{JSON_OUTPUT_TRUNCATED}: re-asking junior task {task.task_id} once with output "
                                   f"cap {raised_cap} (was {e.cap})")
                    continue
                raise json_output_truncated_error(task.task_id, task.persona.value, e, attempt + 1,
                                                  reasked=raised_cap is not None)
            except JuniorEnvelopeInvalid as e:
                # S2-A A1 (register HS-61): a V6 failure is re-asked WITH the parser's message, to the same model
                # (cascade_pos is not advanced), not re-sent blindly; it is not transient, so there is no backoff.
                last_error = str(e)
                invalid_json_attempts += 1
                logger.warning(f"Junior task {task.task_id} returned invalid JSON on attempt {attempt + 1}/"
                               f"{max_retries + 1} with model '{chosen_model}': {e}")
                if attempt < max_retries:
                    reask = JSON_REASK.format(error=e.error[:500])
                    self.junior_reasks.append({
                        "kind": "junior_reask", "task_id": task.task_id, "persona": task.persona.value,
                        "attempt": attempt + 1, "model": chosen_model, "files": list(task.assigned_files),
                        "error": e.error[:500]})
                    continue
                break
            except DeveloperStageError:
                raise  # lane 19 (27a): no LLM -> fail loudly on the first attempt; never retried or re-wrapped
            except stage_deadline.STOP_ERRORS:
                raise  # STAGE-DEADLINE: a stopped stage is never retried or escalated
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Junior task {task.task_id} failed attempt {attempt + 1}/{max_retries + 1} with model '{chosen_model}': {e}")
                if attempt < max_retries:
                    if is_transient_vertex_error(e):
                        backoff = (3.0 * (attempt + 1)) + random.uniform(1.0, 3.0)
                        if len(worker_models) > 1 and chosen_model in worker_models:
                            worker_models.remove(chosen_model)
                        next_model = worker_models[min(cascade_pos + 1, len(worker_models) - 1)]
                        logger.warning(
                            f"Junior task {task.task_id} hit transient Vertex AI error ({e}). "
                            f"Backing off {backoff:.1f}s and cascading to alternate model '{next_model}'..."
                        )
                        await asyncio.sleep(backoff)
                    else:
                        await asyncio.sleep(1.5 * (attempt + 1))
                    cascade_pos += 1
                else:
                    break

        if invalid_json_attempts + truncated_attempts == max_retries + 1:
            # every attempt was invalid JSON (TI5-TRUNC: or the one re-asked truncation): a typed CODE_DEFECT, never
            # a silent drop of the swarm (HS-61)
            raise json_output_invalid_error(task.task_id, task.persona.value, last_error or "", max_retries + 1)
        # If retries failed, escalate to Lead Developer
        logger.error(f"Task {task.task_id} exhausted {max_retries} retries. Escalating to Staff Lead Developer.")
        raise PoisonedContractEscalationError(
            f"Task '{task.task_id}' ({task.persona}) failed repeatedly: {last_error}. "
            "Escalated to Staff Lead Developer for contract amendment."
        )

    async def _call_gemini_with_backoff(
        self,
        prompt: str,
        system_instruction: str,
        model_name: str,
        trace_id: Optional[str] = None,
        intent_task: bool = False,
        intent_max_output_tokens: Optional[int] = None,
    ) -> tuple[Dict[str, str], int]:
        """Calls Gemini API with rate-limiting and error recovery. TI-3: `intent_task` = the IaC persona on the
        typed-intent path (response_json_schema when the setting asks for it). TI5-TRUNC: `intent_max_output_tokens`
        = the raised intent cap of the one truncation re-ask (None: IntentRun.max_output_tokens); an intent answer
        whose finish reason is MAX_TOKENS raises JuniorOutputTruncated before any JSON parse.

        SLOW-CALL-FALLBACK (owner 11-13): the call walks `model_name` then the task's fallback models (`_JUNIOR_CALL`,
        set by invoke_junior_worker; a direct caller walks `model_name` alone) through
        llm_transport.CallWalk (purpose JUNIOR, or IAC for the intent task): each attempt is bounded, a timeout or a
        typed transient status goes to the next model with its own family config, a late answer is never used. No
        answer from the chain raises LlmFallbackExhausted; the answer's model is in the call's provenance."""
        if not self.genai_client:
            # Lane 19 (owner register row 27a): no stub files without an LLM; tests mock the client instead.
            raise DeveloperStageError(LLM_UNAVAILABLE, "no LLM client configured for the developer swarm")

        developer_token_limit = 65536
        thinking_budget = 0
        try:
            from shared.settings import get_platform_settings, thinking_budget_of
            settings = get_platform_settings()  # row SWARM-TOK-1 (was db=: TypeError); PROJECT_ID = host project
            developer_token_limit = settings.models.get_developer_token_limit()
            thinking_budget = thinking_budget_of(settings)   # FD-4CI-b: Settings > Thinking Budget (0 = as before)
        except Exception as e:
            logger.warning(f"Could not load platform settings; developer token limit uses the default: {e}")

        from google.genai import types
        intent_call = bool(intent_task and self.iac_intent is not None)
        settings_token_limit = developer_token_limit
        built: Dict[str, Dict[str, Any]] = {}

        def build_config(m: str) -> Any:
            """The family-specific request of model `m` (Argon compat 10-14; SLOW-CALL-FALLBACK rebuilds it for each
            model of the walk, so a Gemini 4 LEVEL primary and a Gemini 3.x BUDGET fallback each get their own)."""
            limit = max_output_tokens_for(m, settings_token_limit, Purpose.DEVELOPER)
            config_kwargs = dict(
                system_instruction=system_instruction,
                response_mime_type="application/json",
                temperature=0.2,
                max_output_tokens=limit,
            )
            if intent_call:
                # TI-3 cost (smoke diagnosis 10-20): a bounded thinking budget and output bound for the IaC intent call
                intent_cap = (self.iac_intent.max_output_tokens if intent_max_output_tokens is None
                              else intent_max_output_tokens)   # TI5-TRUNC: the raised cap of the truncation re-ask
                config_kwargs["max_output_tokens"] = min(int(limit), int(intent_cap))
                tc = thinking_config_for(m, int(self.iac_intent.thinking_budget), Purpose.DEVELOPER, types=types)
                if tc is not None:
                    config_kwargs["thinking_config"] = tc
                if self.iac_intent.structured_output:
                    config_kwargs["response_json_schema"] = intent_response_json_schema(self.iac_intent.artifacts)
            elif thinking_budget:   # FD-4CI-b: the platform Thinking Budget for the other junior calls (0: none sent)
                tc = thinking_config_for(m, thinking_budget, Purpose.DEVELOPER, types=types)
                if tc is not None:
                    config_kwargs["thinking_config"] = tc
            cfg = types.GenerateContentConfig(**adapt_generate_config_kwargs(m, Purpose.DEVELOPER, config_kwargs,
                                                                             types=types))
            built[m] = {"limit": limit, "kwargs": config_kwargs, "config": cfg}
            return cfg

        # SLOW-CALL-FALLBACK (owner 11-13): each attempt is bounded by its purpose's timeout (and the stage deadline);
        # a timeout or a typed transient status walks to the next model of the task's cascade; a late answer is never
        # used. The call stays here (the eval harness keys its cassettes on this function).
        call_ctx = _JUNIOR_CALL.get()
        # a direct call (no junior task context) walks only its own model, as before (no settings read added)
        chain = [model_name, *call_ctx["fallbacks"]] if call_ctx is not None else [model_name]
        stage_bound, stop = active_stage_bound(self.deadline, self.stage_stop, self._clock)   # RT F3
        walk = CallWalk(chain, purpose=CallPurpose.IAC if intent_call else CallPurpose.JUNIOR, stage="developer",
                        deadline=stage_bound, timeouts=self.call_timeouts, clock=self._clock,
                        stage_stop=stop,
                        abandoned=ledger_abandoned_sink(self.db, trace_id, "developer_swarm"))
        response = None
        try:
            for plan in walk:
                if plan.backoff_s:
                    await (self._async_sleep or asyncio.sleep)(plan.backoff_s)
                legacy_tries = 0
                while True:
                    # STAGE-DEADLINE checkpoint (to_thread carries the stage context); the walk alone sets the call's
                    # http_options (RT F3)
                    stage_deadline.checkpoint("developer.junior")
                    try:
                        response = await asyncio.to_thread(
                            self.genai_client.models.generate_content,
                            model=plan.model,
                            contents=prompt,
                            config=walk.config(plan, build_config(plan.model)),
                        )
                    except stage_deadline.STOP_ERRORS:
                        raise
                    except Exception as rpc_err:
                        outcome = walk.failed(plan, rpc_err)
                        if outcome is not None:
                            logger.warning(f"Junior call to '{plan.model}' {outcome} after "
                                           f"{walk.attempts[-1].elapsed_s:.1f}s; walking to the next model")
                            response = None
                            break
                        # an error the typed rule does not classify keeps today's handling: the same-model retries
                        if is_transient_vertex_error(rpc_err) and legacy_tries < 3:
                            backoff = (2.0 ** legacy_tries) * 1.5 + random.uniform(0.5, 2.0)
                            legacy_tries += 1
                            logger.warning(f"Transient Vertex AI error on model '{plan.model}' (attempt "
                                           f"{legacy_tries}/4): {rpc_err}. Retrying in {backoff:.1f}s...")
                            await (self._async_sleep or asyncio.sleep)(backoff)
                            continue
                        logger.error(f"Unrecoverable or exhausted Vertex AI error on '{plan.model}': {rpc_err}")
                        raise rpc_err
                    if not response:
                        if legacy_tries < 3:   # today: an empty response is asked again (no exception to classify)
                            legacy_tries += 1
                            continue
                        raise RuntimeError(f"Vertex AI call to '{plan.model}' returned empty response without "
                                           f"exception.")
                    if not walk.answered(plan, response):
                        response = None   # arrived after its timeout: never used (its tokens are on the ledger)
                    break
                if response is not None:
                    break
        finally:
            if call_ctx is not None:
                call_ctx["provenance"] = walk.provenance()
        model_name = walk.answered_model or model_name   # the rest reads the answer of the model that wrote it
        developer_token_limit = built[model_name]["limit"]
        config_kwargs = built[model_name]["kwargs"]
        genai_config = built[model_name]["config"]
        self.any_model_answered = True

        if trace_id and self.db:
            try:
                from shared.token_accounting import extract_token_usage, record_agent_tokens
                usage_rec = extract_token_usage(response, model_name)
                record_agent_tokens(self.db, trace_id, "developer_swarm", usage_rec)
            except Exception as t_err:
                logger.debug(f"Failed to record developer swarm tokens: {t_err}")

        if response and hasattr(response, "candidates") and response.candidates:
            candidate = response.candidates[0]
            finish_reason = getattr(candidate, "finish_reason", None)
            # TI5-TRUNC: the API's typed finish reason (a str enum: a recorded "MAX_TOKENS" compares equal), exact
            # equality; the log prints the cap actually sent, not the developer limit.
            if isinstance(finish_reason, str) and finish_reason == types.FinishReason.MAX_TOKENS:
                usage = getattr(response, "usage_metadata", None)
                thoughts = _token_count(usage, "thoughts_token_count")
                answer = _token_count(usage, "candidates_token_count")
                sent_cap = getattr(genai_config, "max_output_tokens", None) or config_kwargs["max_output_tokens"]
                logger.critical(
                    f"TOKEN_LIMIT_EXCEEDED: Swarm worker model '{model_name}' reached output token limit ({sent_cap}; "
                    f"thinking tokens {thoughts}, answer tokens {answer}). File generation truncated."
                )
                if intent_call:
                    # measured like every junior response (Step 1 S1-B V6), without parsing the cut-off text
                    self.envelope_checks.append({"ok": False, "error": f"{JSON_OUTPUT_TRUNCATED}: finish reason "
                                                                      f"MAX_TOKENS at cap {sent_cap}"})
                    raise JuniorOutputTruncated(sent_cap, developer_token_limit, thoughts, answer)

        tokens = 3000
        if hasattr(response, "usage_metadata") and response.usage_metadata:
            tokens = getattr(response.usage_metadata, "total_token_count", 3000) or 3000

        raw_text = response.text.strip() if response and response.text else "{}"
        clean_json = re.sub(r"^```json\s*", "", raw_text)
        clean_json = re.sub(r"\s*```$", "", clean_json)
        if self.iac_intent is not None:   # TI-3: an intent given as a JSON object becomes its canonical text
            clean_json = normalize_intent_envelope(clean_json)
        # Step 1 S1-B V6 (measurement on the generation path; control flow unchanged until S1-D1): does this exact
        # clean_json satisfy the junior envelope contract?
        check = envelope_check(clean_json)
        self.envelope_checks.append(check)
        try:
            parsed = json.loads(clean_json)
        except json.JSONDecodeError as e:   # S2-A A1 (HS-61): typed, so the retry re-asks with the parser's message
            raise JuniorEnvelopeInvalid(f"{type(e).__name__}: {e}") from e

        files = parsed.get("files", {})
        if not isinstance(files, dict):
            files = {}
        return files, tokens

    def invoke_repair(self, persona: str, system_instruction: str, prompt: str, model_name: str,
                      max_output_tokens: int, trace_id: Optional[str] = None,
                      thinking_budget: Optional[int] = None, deadline: Optional[float] = None,
                      sizing: Optional[Callable[[str], Tuple[int, Optional[int]]]] = None,
                      repair_deadline: Optional[float] = None,
                      stage_stop: Optional[Callable[[str], BaseException]] = None) -> Dict[str, Any]:
        """One bounded repair call for one persona (Step 1 S1-B RepairTask). Synchronous; no retry of an answer (the
        repair loop owns the budget). Returns {"files", "envelope_ok", "error", "finish_reason", "tokens_in",
        "tokens_out", "tokens_thoughts", "model", "transport_attempts", "model_fallback_reason", "model_attempts",
        "tokens_abandoned_in", "tokens_abandoned_out"}; a transport error, an unfinished response (finish reason other than STOP) or an invalid
        envelope (V6) is reported, never raised.

        SLOW-CALL-FALLBACK (owner 11-13): the call walks `model_name` then the developer cascade after it
        (llm_transport.CallWalk, purpose REPAIR): a timeout or a typed transient status (429/5xx; R3c) goes to the
        next model, a transient on the last model is retried after REPAIR_RETRY_BACKOFF_S. `model` in the result is
        the model that answered. Each fallback model gets its own bound: `sizing(model)` -> (max_output_tokens,
        thinking_budget) (the caller re-sizes the task for that model's family); without it the task's values go
        through the family rules. A chain with no answer is reported (LLM_FALLBACK_EXHAUSTED); a stage `deadline`
        (absolute time.monotonic()) with no room left raises LlmStageBudgetExhausted. RT F6: `repair_deadline` (the
        dispatch's repair wall clock, absolute time.monotonic()) also bounds the walk; when it is the binding bound and
        leaves no room, the call is reported (error_code REPAIR_WALL_CLOCK) and the loop's own wall-clock check stops.

        Bound: Vertex counts thinking tokens inside max_output_tokens, so `max_output_tokens` is the bound on
        candidates + thoughts and `thinking_budget` (< max_output_tokens) reserves the rest for the answer; without
        it the model thought until the bound and the answer was cut off (R3, 10-13)."""
        out: Dict[str, Any] = {"files": {}, "envelope_ok": False, "error": None, "finish_reason": None,
                               "tokens_in": 0, "tokens_out": 0, "tokens_thoughts": 0, "model": model_name,
                               "persona": persona}
        if not self.genai_client:
            out["error"] = "no LLM client"
            return out
        from google.genai import types

        def build_config(m: str) -> Any:
            if m == model_name or sizing is None:
                cap, budget = int(max_output_tokens), thinking_budget
            else:
                cap, budget = sizing(m)
                cap = int(cap)
            config_kwargs: Dict[str, Any] = {"system_instruction": system_instruction,
                                             "response_mime_type": "application/json", "temperature": 0.2,
                                             "max_output_tokens": cap}
            if budget is not None:
                if not 0 < int(budget) < cap:
                    raise ValueError(f"thinking_budget {budget} must be in (0, max_output_tokens {cap})")
                tc = thinking_config_for(m, int(budget), Purpose.REPAIR, types=types)
                if tc is not None:
                    config_kwargs["thinking_config"] = tc
            # Gemini <= 3.x: config_kwargs unchanged. Gemini 4 Argon: thinking_level LOW instead of the budget (a
            # budget is HTTP 400), no temperature (ignored), max_output_tokens already sized by
            # repair_call_max_output_tokens.
            return types.GenerateContentConfig(**adapt_generate_config_kwargs(m, Purpose.REPAIR, config_kwargs,
                                                                              types=types))

        try:
            build_config(model_name)
        except ValueError as e:
            out["error"] = str(e)
            return out
        try:
            chain = _chain_after(model_name, list(get_model_cascade_for_agent("developer")))
        except Exception:  # noqa: BLE001 - settings unreadable: the one model
            chain = [model_name]
        deadline, stage_stop = active_stage_bound(deadline, stage_stop, self._clock)   # RT F3
        bounds = [b for b in (deadline, repair_deadline) if b is not None]
        stage_binds = repair_deadline is None or (deadline is not None and deadline < repair_deadline)
        walk = CallWalk(chain, purpose=CallPurpose.REPAIR, stage="developer", deadline=min(bounds) if bounds else None,
                        stage_stop=stage_stop if stage_binds else None,   # RT F5: only the stage's own time
                        timeouts=self.call_timeouts, clock=self._clock,
                        abandoned=ledger_abandoned_sink(self.db, trace_id, "developer_repair"))
        response = None
        try:
            for plan in walk:
                if plan.backoff_s:
                    getattr(self, "_repair_sleep", time.sleep)(plan.backoff_s)
                try:
                    config = build_config(plan.model)
                except ValueError as e:   # a fallback model's sizing that is not a valid bound: reported
                    out["error"] = f"{plan.model}: {e}"
                    break
                # STAGE-DEADLINE checkpoint, outside the try (a stop is raised, never reported); the walk alone
                # sets the call's http_options (RT F3)
                stage_deadline.checkpoint("developer.repair")
                try:
                    response = self.genai_client.models.generate_content(model=plan.model, contents=prompt,
                                                                         config=walk.config(plan, config))
                except stage_deadline.STOP_ERRORS:
                    raise
                except Exception as e:  # noqa: BLE001
                    # R3c: a transient provider status (the SDK's APIError.code, an int: 429/500/503/504) carries no
                    # usage, so the token ledger is unaffected; it now walks to the next model. Anything else fails
                    # at once (reported).
                    if walk.failed(plan, e) is not None:
                        response = None
                        continue
                    out["error"] = f"{type(e).__name__}: {str(e)[:500]}"
                    response = None
                    break
                if walk.answered(plan, response):
                    break
                response = None   # arrived after its timeout: never merged (its billed tokens are on the ledger)
        except LlmFallbackExhausted as e:
            out["error"] = f"{type(e).__name__}: {str(e)[:900]}"
            out["error_code"] = e.reason
        except LlmStageBudgetExhausted as e:
            if repair_deadline is None or (deadline is not None and deadline < repair_deadline):
                raise   # the stage's own time is gone: a typed stop of the stage
            out["error"] = f"{REPAIR_WALL_CLOCK}: the repair wall clock left no room for a call: {str(e)[:700]}"
            out["error_code"] = REPAIR_WALL_CLOCK
        finally:
            out["transport_attempts"] = len(walk.attempts)
            # REPAIR-WALL-CLOCK-ROOM (RT F1): the requests actually started; a walk refused for lack of room records a
            # NO_STAGE_BUDGET attempt without calling the model, so transport_attempts alone cannot tell
            out["calls_started"] = sum(1 for a in walk.attempts if a.outcome != NO_STAGE_BUDGET)
            out["model_attempts"] = [a.to_dict() for a in walk.attempts]
            out["model_fallback_reason"] = walk.fallback_reason
            # RT F9: a late (unused) answer was billed: its prompt and its output, each where it belongs
            out["tokens_abandoned_in"] = sum(int(a.prompt_tokens or 0) for a in walk.attempts if a.late)
            out["tokens_abandoned_out"] = sum(int(a.output_tokens or 0) for a in walk.attempts if a.late)
        if response is None:
            if not out["error"]:
                out["error"] = "no answer"
            return out
        model_name = walk.answered_model or model_name
        out["model"] = model_name
        usage = getattr(response, "usage_metadata", None)
        if usage is not None:
            prompt_n = int(getattr(usage, "prompt_token_count", 0) or 0)
            cand_n = int(getattr(usage, "candidates_token_count", 0) or 0)
            thoughts_n = int(getattr(usage, "thoughts_token_count", 0) or 0)
            total_n = int(getattr(usage, "total_token_count", 0) or 0)
            out["tokens_in"] = prompt_n
            out["tokens_thoughts"] = thoughts_n
            # billed output = max(candidates + thoughts, total - prompt): a response that reports total_token_count
            # but omits candidates_token_count (blocked / empty candidate) is not under-counted in the ledger
            out["tokens_out"] = max(cand_n, total_n - prompt_n - thoughts_n, 0)
        if trace_id and self.db:
            try:
                from shared.token_accounting import extract_token_usage, record_agent_tokens
                record_agent_tokens(self.db, trace_id, "developer_repair", extract_token_usage(response, model_name))
            except Exception as t_err:  # noqa: BLE001
                logger.debug(f"Failed to record repair tokens: {t_err}")
        candidates = getattr(response, "candidates", None) or []
        reason = getattr(candidates[0], "finish_reason", None) if candidates else None
        if reason is not None:
            out["finish_reason"] = str(getattr(reason, "value", reason))
        if out["finish_reason"] not in (None, "STOP"):
            out["error"] = f"FINISH_REASON_{out['finish_reason']}: the model did not finish the answer"
            return out
        raw_text = (getattr(response, "text", None) or "").strip() or "{}"
        clean_json = re.sub(r"^```json\s*", "", raw_text)
        clean_json = re.sub(r"\s*```$", "", clean_json)
        if self.iac_intent is not None:   # TI-3: an intent given as a JSON object becomes its canonical text
            clean_json = normalize_intent_envelope(clean_json)
        check = envelope_check(clean_json)
        out["envelope_ok"] = check["ok"]
        if not check["ok"]:
            out["error"] = check["error"]
            return out
        out["files"] = JuniorFilesEnvelope.model_validate(json.loads(clean_json)).files
        return out

    async def execute_phased_junior_swarm(
        self,
        plan: LeadDeveloperDecompositionPlan,
        trace_id: str,
        product_id: str,
        model_name: str = "gemini-3.7-flash",
    ) -> Dict[str, str]:
        """
        Coordinates the multi-wave swarm execution:
        1. Sequentially loops through waves (1 -> 2 -> 3).
        2. Dispatches workers concurrently within each wave under an asyncio semaphore.
        3. Enforces disjoint file staging & collision protection.
        4. Injects surgical read_dependencies from earlier waves.
        5. Emits real-time DeveloperSwarmStageTelemetry into pipeline_executions/{trace_id}.
        6. Persists individual junior traces to stage_traces for Glass Pane inspection.
        7. Meters tokens against the FinOps envelope.
        """
        staged_repository_tree: Dict[str, str] = {}
        cumulative_tokens = 0

        # Seed Wave 0 immutable shared contracts into repository tree before Wave 1
        if hasattr(plan, "wave_0_contract_files") and plan.wave_0_contract_files:
            staged_repository_tree.update(plan.wave_0_contract_files)
            logger.info(
                f"Seeded {len(plan.wave_0_contract_files)} Wave 0 immutable contract files into repository tree for {product_id}."
            )

        # Group tasks by wave
        waves: Dict[int, List[JuniorTaskAssignment]] = {}
        for task in plan.tasks:
            waves.setdefault(task.wave, []).append(task)

        sorted_waves = sorted(waves.keys())
        total_waves = len(sorted_waves)

        # Build initial structured DeveloperSwarmStageTelemetry
        file_attribution = {f: t.persona.value for t in plan.tasks for f in t.assigned_files}
        if hasattr(plan, "wave_0_contract_files") and plan.wave_0_contract_files:
            for f in plan.wave_0_contract_files:
                if f not in file_attribution:
                    file_attribution[f] = "LEAD_DEVELOPER"
        # Step 1 S1-A: the assembly records which persona wrote each draft file (provenance comment, repair routing)
        self.last_file_attribution = dict(file_attribution)
        waves_telemetry = []
        for w_idx in sorted_waves:
            w_tasks = waves[w_idx]
            wave_name = "Contracts & Core Layer" if w_idx == 1 else ("Core Implementation & UI Layer" if w_idx == 2 else "Quality & Delivery Layer")
            task_telemetries = [
                {
                    "task_id": t.task_id,
                    "persona": t.persona.value,
                    "wave": t.wave,
                    "status": "PENDING",
                    "elapsed_seconds": 0.0,
                    "output_tokens": 0,
                    "assigned_files": t.assigned_files,
                    "retry_count": 0,
                    "error_message": None,
                }
                for t in w_tasks
            ]
            waves_telemetry.append({
                "wave_index": w_idx,
                "wave_name": wave_name,
                "status": "PENDING",
                "elapsed_seconds": 0.0,
                "tasks": task_telemetries,
            })

        swarm_state = {
            "execution_mode": plan.execution_mode.value,
            "current_wave": 1,
            "total_waves": total_waves,
            "total_tokens_consumed": 0,
            "max_tokens_budget": plan.max_swarm_token_envelope,
            "circuit_breaker_tripped": False,
            "waves": waves_telemetry,
            "file_attribution": file_attribution,
        }

        # Seed initial state into Firestore
        if self.db and trace_id:
            try:
                self.db.collection("pipeline_executions").document(trace_id).set({
                    "stages": {
                        "developer": {
                            "details": {
                                "swarm": swarm_state
                            }
                        }
                    }
                }, merge=True)
                if product_id:
                    self.db.collection("workloads").document(product_id).set({
                        "file_attribution": file_attribution
                    }, merge=True)
            except Exception as e:
                logger.debug(f"Initial swarm telemetry write notice: {e}")

        for wave_idx, wave_num in enumerate(sorted_waves):
            current_tasks = waves[wave_num]
            # STAGE-DEADLINE: no wave starts after the stage deadline (or once the stage is abandoned)
            stage_deadline.checkpoint(f"developer.wave_{wave_num}")
            stage_deadline.mark(f"developer.wave_{wave_num}", tasks=[t.task_id for t in current_tasks])
            wave_start_time = time.time()
            logger.info(f"Dispatching Swarm Wave {wave_num}/{total_waves} ({len(current_tasks)} tasks) for {product_id}")

            swarm_state["current_wave"] = wave_num
            if wave_idx < len(swarm_state["waves"]):
                swarm_state["waves"][wave_idx]["status"] = "RUNNING"

            self._persist_swarm_state(trace_id, swarm_state)

            async def _run_task(task: JuniorTaskAssignment):
                async with self.semaphore:
                    # Update task status to RUNNING under state lock
                    async with self._state_lock:
                        self._update_task_state(swarm_state, wave_idx, task.task_id, "RUNNING")
                        self._persist_swarm_state(trace_id, swarm_state)

                    # Surgical Dependency Slicing: only provide text of declared read_dependencies
                    deps = {
                        p: staged_repository_tree[p]
                        for p in task.read_dependencies
                        if p in staged_repository_tree
                    }
                    if deps and self.read_view is not None:   # COMMITTED-READ-VIEW: what the commit will hold
                        deps = await self._committed_deps(task, deps)
                    try:
                        result = await self.invoke_junior_worker(task, plan, deps, model_name, trace_id=trace_id)
                    except TypeError:
                        result = await self.invoke_junior_worker(task, plan, deps, model_name)

                    # Update task status to SUCCEEDED under state lock
                    async with self._state_lock:
                        self._update_task_state(
                            swarm_state, wave_idx, task.task_id, "SUCCEEDED",
                            tokens=result.consumed_tokens, elapsed=result.duration_seconds,
                            model=getattr(result, "model", None),
                            fallback_reason=getattr(result, "model_fallback_reason", None),
                        )
                        self._persist_swarm_state(trace_id, swarm_state)
                        # SLOW-CALL-FALLBACK: which model wrote this task's files (and why, when it was a fallback)
                        self.task_provenance.append({
                            "output": task.task_id, "task_id": task.task_id, "persona": task.persona.value,
                            "model": getattr(result, "model", None) or model_name,
                            "primary_model": model_name,
                            "fallback": bool(getattr(result, "model", None)) and result.model != model_name,
                            "fallback_reason": getattr(result, "model_fallback_reason", None)})
                    self._persist_junior_stage_trace(trace_id, task, result)
                    stage_deadline.mark("developer.junior_done", task_completed=task.task_id,
                                        seconds=result.duration_seconds)
                    return task, result

            wave_results = await asyncio.gather(*[_run_task(t) for t in current_tasks], return_exceptions=True)

            for item in wave_results:
                if isinstance(item, Exception):
                    logger.error(f"Wave {wave_num} encountered fatal error: {item}")
                    if wave_idx < len(swarm_state["waves"]):
                        swarm_state["waves"][wave_idx]["status"] = "FAILED"
                    self._persist_swarm_state(trace_id, swarm_state)
                    raise item

                task, res = item
                # Guardrail 1: Enforce disjoint partitions and stage files safely
                stage_junior_files(staged_repository_tree, task, res.files)

                # Guardrail 5: Meter cumulative tokens against FinOps budget envelope
                cumulative_tokens += res.consumed_tokens
                swarm_state["total_tokens_consumed"] = cumulative_tokens

                if cumulative_tokens > (plan.max_swarm_token_envelope * 1.10):
                    swarm_state["circuit_breaker_tripped"] = True
                    self._persist_swarm_state(trace_id, swarm_state)
                    raise FinOpsCircuitBreakerError(
                        f"FinOps Circuit Breaker Tripped: Swarm cumulative tokens ({cumulative_tokens:,}) "
                        f"exceeded 110% of budget envelope ({plan.max_swarm_token_envelope:,})."
                    )

            if wave_idx < len(swarm_state["waves"]):
                swarm_state["waves"][wave_idx]["status"] = "SUCCEEDED"
                swarm_state["waves"][wave_idx]["elapsed_seconds"] = round(time.time() - wave_start_time, 2)
            self._persist_swarm_state(trace_id, swarm_state)

        # SCHEMAS-COLLISION (review F1): the Wave 0 schemas/__init__.py re-exports only the schema modules produced
        wave0 = getattr(plan, "wave_0_contract_files", None) or {}
        if wave0:
            rerender_service_inits(staged_repository_tree, wave0, [f for t in plan.tasks for f in t.assigned_files])

        logger.info(
            f"Swarm successfully synthesized {len(staged_repository_tree)} files "
            f"across {total_waves} waves ({cumulative_tokens:,} tokens consumed)."
        )
        return staged_repository_tree

    async def _committed_deps(self, task: JuniorTaskAssignment, deps: Dict[str, str]) -> Dict[str, str]:
        """COMMITTED-READ-VIEW: `deps` through `read_view`, off the event loop (RT F5: the view may read the workload
        record / platform settings once; to_thread carries the context). L3: the view only changes what this junior
        reads, never the draft, the assembly or the commit, so an unexpected error in it falls back to the staged
        texts (typed warning COMMITTED_READ_VIEW_FAILED) instead of failing the wave; a stage stop still propagates."""
        try:
            viewed = await asyncio.to_thread(self.read_view, deps)
        except stage_deadline.STOP_ERRORS:
            raise
        except Exception as view_err:  # noqa: BLE001 - advisory view: the staged texts are what the junior reads
            logger.warning(f"COMMITTED_READ_VIEW_FAILED task {task.task_id}: {type(view_err).__name__}: "
                           f"{str(view_err)[:300]}; the junior reads its dependencies as staged")
            return deps
        if not isinstance(viewed, dict) or set(viewed) != set(deps):
            logger.warning(f"COMMITTED_READ_VIEW_FAILED task {task.task_id}: the view returned "
                           f"{type(viewed).__name__} with other paths; the junior reads its dependencies as staged")
            return deps
        return viewed

    def _update_task_state(
        self,
        swarm_state: Dict[str, Any],
        wave_idx: int,
        task_id: str,
        status: str,
        tokens: int = 0,
        elapsed: float = 0.0,
        model: Optional[str] = None,
        fallback_reason: Optional[str] = None,
    ) -> None:
        if wave_idx < len(swarm_state.get("waves", [])):
            for t in swarm_state["waves"][wave_idx].get("tasks", []):
                if t.get("task_id") == task_id:
                    t["status"] = status
                    if tokens:
                        t["output_tokens"] = tokens
                    if elapsed:
                        t["elapsed_seconds"] = elapsed
                    if model:   # SLOW-CALL-FALLBACK: the model that wrote the task's files
                        t["model"] = model
                        t["fallback_reason"] = fallback_reason
                    break

    def _persist_swarm_state(self, trace_id: Optional[str], swarm_state: Dict[str, Any]) -> None:
        if not self.db or not trace_id:
            return
        try:
            self.db.collection("pipeline_executions").document(trace_id).set({
                "stages": {
                    "developer": {
                        "details": {
                            "swarm": swarm_state
                        }
                    }
                }
            }, merge=True)
        except Exception as e:
            logger.debug(f"Could not persist swarm state for {trace_id}: {e}")

    def _persist_junior_stage_trace(
        self,
        trace_id: Optional[str],
        task: JuniorTaskAssignment,
        res: JuniorExecutionResult,
    ) -> None:
        if not self.db or not trace_id:
            return
        try:
            from datetime import datetime, timezone
            subagent_key = task.persona.value.lower()
            trace_doc = f"developer_junior_{subagent_key}"
            trace_payload = {
                "trace_id": trace_id,
                "stage_name": "developer",
                "subagent_persona": task.persona.value,
                "rendered_prompt": res.rendered_prompt or "",
                "agent_output": json.dumps({"files": res.files}, indent=2),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "output_tokens": res.consumed_tokens,
                "duration_seconds": res.duration_seconds,
                "is_few_shot_candidate": False,
                "task_id": task.task_id,   # STAGE-TRACE-BY-TASK (additive field)
                "wave": task.wave,
                # SLOW-CALL-FALLBACK: which model wrote this output, and why when it was a fallback
                "model": getattr(res, "model", None),
                "model_fallback_reason": getattr(res, "model_fallback_reason", None),
                "model_attempts": list(getattr(res, "model_attempts", None) or []),
            }
            traces = self.db.collection("pipeline_executions").document(trace_id).collection("stage_traces")
            # STAGE-TRACE-BY-TASK (owner 11-13): one record per task, so two tasks of one persona (11-13 ex08: wave 1
            # and wave 2 BACKEND_ENGINEER) no longer overwrite each other. The persona record the Control Center's
            # agent view reads (`developer_junior_<persona>`, the persona's latest task) is kept as before.
            traces.document(junior_task_trace_doc_id(task.task_id)).set(trace_payload, merge=True)
            traces.document(trace_doc).set(trace_payload, merge=True)
        except Exception as e:
            logger.debug(f"Could not persist junior stage trace for {task.task_id}: {e}")
