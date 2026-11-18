"""
Project Castor: Lead Staff Developer Orchestrator
Decomposes complex architectural specifications into a frozen-contract, multi-wave Work Breakdown Structure (WBS)
with disjoint file assignments and surgical dependency injection.
"""

import json
import logging
import os
import random
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
from google.cloud import firestore

import stage_deadline   # STAGE-DEADLINE (gateway root module)
from .swarm_schemas import (
    JuniorPersona,
    JuniorTaskAssignment,
    LeadDeveloperDecompositionPlan,
    SwarmExecutionMode,
)
from .workload_test_layout import (LEAD_TEST_LAYOUT_REASK, ROOT_TESTS_DIR, is_multi_service, lead_prompt_rule,
                                   root_test_assignments, service_tests_dir)
from .iac_intent_contract import INTENT_PATH, LEAD_INTENT_REASK, iac_hcl_assignments   # TI-3
from .errors import DeveloperStageError
# SLOW-CALL-FALLBACK (owner 11-13): the per-call timeout and typed fallback outcome of the WBS call
from .llm_transport import TIMEOUT, CallPurpose, CallWalk, active_stage_bound, ledger_abandoned_sink

try:
    from shared.settings import get_model_cascade_for_agent
    from shared.cooldown_manager import (
        wait_for_rate_limit_cooldown,
        is_rate_limit_error,
        is_model_deprecated_error,
        is_transient_vertex_error,
    )
except ImportError:
    try:
        from ..shared.settings import get_model_cascade_for_agent
        from ..shared.cooldown_manager import (
            wait_for_rate_limit_cooldown,
            is_rate_limit_error,
            is_model_deprecated_error,
            is_transient_vertex_error,
        )
    except ImportError:
        def get_model_cascade_for_agent(agent_name, project_id=None):
            return ["gemini-4-carbon", "gemini-4-argon"]
        def wait_for_rate_limit_cooldown(*args, **kwargs):
            return False
        def is_rate_limit_error(e):
            return "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e).upper()
        def is_model_deprecated_error(e):
            return "404" in str(e) or "NOT_FOUND" in str(e).upper()
        def is_transient_vertex_error(e):
            if e is None:
                return False
            err_str = str(e).lower()
            return any(k in err_str for k in ["429", "500", "502", "503", "504", "harpoon", "resource_exhausted", "internal error", "unavailable"])

try:
    from .contract_registry import SharedContractRegistry, plan_services, reserved_assignments
except ImportError:
    try:
        from contract_registry import SharedContractRegistry, plan_services, reserved_assignments
    except ImportError:
        SharedContractRegistry = None

logger = logging.getLogger("castor-lead-orchestrator")

# SCHEMAS-COLLISION (owner 10-28): the re-ask note for a plan that assigned a platform-owned Wave 0 schema path
# (contract_registry.reserved_assignments); like LEAD_INTENT_REASK it replaces the previous note, never stacks.
LEAD_SCHEMAS_REASK = ("\n\nERROR SCHEMAS.RESERVED_PATH_ASSIGNED: the previous plan assigned {paths}. The platform "
                      "writes the shared contract package `apps/<service>/schemas/` (`__init__.py`, `contracts.py`) "
                      "and `contracts/` itself, and a module `apps/<service>/schemas.py` beside that package is never "
                      "imported. Return the whole plan again without those paths: put shared models in "
                      "`apps/<service>/schemas/<name>.py` (re-exported from `schemas/__init__.py`, so "
                      "`from schemas import Name` keeps working) and keep every other assignment.")


LEAD_ORCHESTRATOR_SYSTEM_PROMPT = """You are StackVend's Staff Lead Developer Agent.
Your responsibility is NOT to write all the code yourself. Instead, you act as the Engineering Lead:
1. Digest the architectural specification and task DAG.
2. Establish strict, frozen INTERFACE CONTRACTS (Pydantic data models, OpenAPI routes, OpenTofu module parameters).
3. Create a phased Work Breakdown Structure (WBS) delegating file creation across 3 sequential waves:
   - Wave 1: Foundations & Database (schemas, CRUD models, base IAM/secrets).
   - Wave 2: Core Services & Frontend (FastAPI routes, business logic, UI views, Cloud Run IaC).
   - Wave 3: Test Engineering & CI/CD Packaging (Pytest fixtures, unit tests, Cloud Buildpacks manifests).

### CRITICAL WBS INVARIANTS:
1. **DISJOINT FILE PARTITIONS (MUTUALLY EXCLUSIVE ASSIGNMENTS)**:
   - No two tasks can ever be assigned the same file path: Files(Task_i) ∩ Files(Task_j) = ∅.
   - If two juniors touch the same file, your plan is invalid and will be rejected.
2. **SURGICAL READ DEPENDENCIES**:
   - For Wave 2 and Wave 3 tasks, declare explicit `read_dependencies` specifying the exact file paths from prior waves that this worker needs to read to ensure type parity and test accuracy.
3. **ZERO DOCKERFILES MANDATE**:
   - NEVER assign a `Dockerfile`, `Dockerfile.*`, or `.dockerignore`. All workloads use Google Cloud Buildpacks via `Procfile` and `requirements.txt`.
4. **FILE BUDGET CEILING**:
   - Assign only 2 to 5 related files per task to prevent context saturation.
5. **PLATFORM-OWNED SHARED SCHEMAS PACKAGE**:
   - The platform writes the Wave 0 shared contracts itself: `contracts/__init__.py`, `contracts/schemas.py` and, in every service, the package `apps/<service>/schemas/` (`schemas/__init__.py`, `schemas/contracts.py`). NEVER assign those files, and NEVER assign a module `apps/<service>/schemas.py` (Python imports the package, so that module would never load).
   - Put further shared models in `apps/<service>/schemas/<name>.py`: the platform re-exports each of them from `schemas/__init__.py`, so `from schemas import Name` works in every file of the service.

You must respond strictly with a single valid JSON object adhering to this schema:
{
  "execution_mode": "STANDARD_SWARM" or "ENTERPRISE_SWARM" or "SOLO_FAST_PATH",
  "max_swarm_token_envelope": 350000,
  "shared_contracts": {
    "data_models": "class Item(BaseModel): ...",
    "api_routes": "GET /api/v1/items, POST /api/v1/items"
  },
  "lead_notes": "Architectural guidelines for the swarm",
  "tasks": [
    {
      "task_id": "task-db-models",
      "persona": "DATABASE_ENGINEER",
      "wave": 1,
      "assigned_files": ["apps/product/models.py", "apps/product/db.py"],
      "read_dependencies": [],
      "task_objective": "Implement database client and Pydantic models",
      "injected_contracts": {},
      "specific_guardrails": ["Use Firestore client with retry logic"]
    },
    {
      "task_id": "task-backend-api",
      "persona": "BACKEND_ENGINEER",
      "wave": 2,
      "assigned_files": ["apps/product/main.py", "apps/product/routers/items.py"],
      "read_dependencies": ["apps/product/models.py", "apps/product/db.py"],
      "task_objective": "Implement FastAPI application routes",
      "injected_contracts": {},
      "specific_guardrails": ["Enforce HTTP 400/404 handling"]
    },
    {
      "task_id": "task-iac-workload",
      "persona": "IAC_ENGINEER",
      "wave": 2,
      "assigned_files": ["infra/workload/main.tf", "infra/workload/variables.tf"],
      "read_dependencies": [],
      "task_objective": "Assemble Cloud Run and Firestore OpenTofu infrastructure",
      "injected_contracts": {},
      "specific_guardrails": ["Zero public IPs, include startupProbe"]
    },
    {
      "task_id": "task-qa-tests",
      "persona": "TEST_ENGINEER",
      "wave": 3,
      "assigned_files": ["tests/test_api.py", "tests/conftest.py"],
      "read_dependencies": ["apps/product/main.py", "apps/product/models.py"],
      "task_objective": "Author pytest test fixtures and API contract tests",
      "injected_contracts": {},
      "specific_guardrails": ["Mock all GCP Firestore calls"]
    },
    {
      "task_id": "task-devops-build",
      "persona": "DEVOPS_ENGINEER",
      "wave": 3,
      "assigned_files": ["Procfile", "requirements.txt", ".gcloudignore", "cloudbuild.yaml"],
      "read_dependencies": ["apps/product/main.py"],
      "task_objective": "Create Google Cloud Buildpacks manifests and Cloud Build YAML",
      "injected_contracts": {},
      "specific_guardrails": ["Strictly ZERO Dockerfiles"]
    }
  ]
}
"""


# The solo fast path is for a specification shorter than this many characters; the one place the threshold is written.
SOLO_FAST_PATH_SPEC_CHAR_LIMIT = 1500


def spec_rules_out_solo_fast_path(spec_text: str) -> bool:
    """True when `decompose_specification` cannot take its solo fast path for this specification, whatever the Task DAG
    and the repository hold. The gateway uses the same rule to decide which RESUME_DEVELOPER dispatches get the kept
    Task DAG (RESUME-DEVELOPER-TASK-DAG), so that giving the DAG never changes this selection."""
    return len(spec_text) >= SOLO_FAST_PATH_SPEC_CHAR_LIMIT


class LeadDeveloperOrchestrator:
    def __init__(
        self,
        genai_client: Optional[Any] = None,
        model_name: str = "gemini-3.7-flash",
        db: Optional[firestore.Client] = None,
        project_id: Optional[str] = None,
    ):
        self.genai_client = genai_client
        self.model_name = model_name
        self.db = db
        self.project_id = project_id or os.getenv("PROJECT_ID")
        # SLOW-CALL-FALLBACK: the model that wrote the last plan ({output, model, primary_model, fallback,
        # fallback_reason, attempts}; model None = the deterministic fallback plan) and the injectable clock
        self.last_model_provenance: Optional[Dict[str, Any]] = None
        self._clock = time.monotonic
        self._sleep = time.sleep   # RT F10: the one same-model retry's wait (tests: no real waiting)

    def fetch_active_golden_modules(self) -> List[Dict[str, Any]]:
        """Queries Firestore for active enterprise golden modules to inject into IaC context."""
        modules = []
        if self.db:
            try:
                docs = self.db.collection("golden_modules").stream()
                for doc in docs:
                    d = doc.to_dict() or {}
                    if d.get("status", "ACTIVE") == "ACTIVE":
                        modules.append({
                            "module_id": doc.id,
                            "name": d.get("name", doc.id),
                            "description": d.get("description", ""),
                            "required_inputs": d.get("required_inputs", []),
                            "outputs": d.get("outputs", []),
                        })
            except Exception as e:
                logger.debug(f"Could not load golden modules from Firestore: {e}")
        return modules

    def decompose_specification(
        self,
        product_id: str,
        spec_text: str,
        task_dag: List[Dict[str, Any]],
        plan_markdown: Optional[str] = None,
        iac_engine: str = "OPENTOFU",
        vcs_provider: str = "GITHUB",
        existing_files: Optional[Dict[str, str]] = None,
        trace_id: Optional[str] = None,
        service_names: Optional[Iterable[str]] = None,
        wiring_contract: Optional[str] = None,
        probe_rule: Optional[str] = None,
        iac_intent_rule: Optional[str] = None,
        app_auth_rule: Optional[str] = None,
        deadline: Optional[float] = None,
        stage_stop: Optional[Any] = None,
    ) -> LeadDeveloperDecompositionPlan:
        """
        Analyzes the architectural plan and decomposes it into a hardened, disjoint WBS plan.

        ``service_names``: the workload's typed service list (``ComputeIntent.service_names``). With more than one
        service the decomposition prompt gains the per-service test layout rule and the deterministic fallback puts
        its tests under ``apps/<svc>/tests/`` (row L3-PRB-t); with one or none both are byte-identical to before.

        ``iac_intent_rule`` (TI-3, typed-intent mode only; iac_intent_contract.lead_intent_rule): appended to the
        decomposition prompt; a plan that still assigns a .tf / .tf.json file under infra/ is refused (re-asked on
        the next model with the exact paths) and the deterministic fallback assigns the IaC task the intent file.
        None = prompt, plan handling and fallback byte-identical to before.

        ``app_auth_rule`` (DIRECT-IAP-SKILL-VERIFY, Direct IAP Cloud Run only; prompt.direct_iap_auth_rule): appended to the
        decomposition prompt so task contracts do not ask for an audience variable or a mock-auth flag. None or "" =
        byte-identical prompt.

        SCHEMAS-COLLISION (owner 10-28): a plan that assigns a Wave 0 registry file or `apps/<svc>/schemas.py` (the
        module the registry's `schemas/` package would shadow; contract_registry.reserved_assignments) is refused and
        re-asked on the next model with the exact paths (LEAD_SCHEMAS_REASK), like the TI-3 HCL rule.

        SLOW-CALL-FALLBACK (owner 11-13): every model call is bounded (llm_transport.CallWalk, purpose WBS, capped by
        ``deadline``: an absolute time.monotonic(), None = no stage bound). A timed-out call (or an answer that came
        after its timeout, never used) prunes that model and the loop asks the next one; a typed transient status is
        handled as before (next model, cooldown cycles when every model is rate limited). When no model answered and a
        call timed out, LlmFallbackExhausted is raised (every attempt listed) instead of the deterministic plan.
        """
        service_names = tuple(service_names or ())
        existing_files = existing_files or {}
        golden_modules = self.fetch_active_golden_modules()

        # Resolve FinOps token envelope and token limit from platform settings
        configured_envelope = 350_000
        developer_token_limit = 65536
        thinking_budget = 0
        try:
            from shared.settings import get_platform_settings, thinking_budget_of
            p_settings = get_platform_settings(project_id=self.project_id)  # row SWARM-TOK-1 (was db=: TypeError)
            if p_settings and hasattr(p_settings, "models"):
                if getattr(p_settings.models, "max_swarm_token_envelope", None):
                    configured_envelope = int(p_settings.models.max_swarm_token_envelope)
                developer_token_limit = p_settings.models.get_developer_token_limit()
                thinking_budget = thinking_budget_of(p_settings)   # FD-4CI-b: Settings > Thinking Budget
        except Exception as e:
            logger.warning(f"Could not load platform settings; swarm envelope/token limit use defaults: {e}")

        # Fast-Path Check: Very simple single-file bug fix / modification
        if len(task_dag) <= 1 and len(existing_files) > 0 and not spec_rules_out_solo_fast_path(spec_text):
            logger.info(f"Workload '{product_id}' classified as SOLO_FAST_PATH (lightweight modification).")
            return LeadDeveloperDecompositionPlan(
                execution_mode=SwarmExecutionMode.SOLO_FAST_PATH,
                iac_engine=iac_engine,
                vcs_provider=vcs_provider,
                max_swarm_token_envelope=min(100_000, configured_envelope),
                shared_contracts={},
                tasks=[],
                lead_notes="Solo fast path selected. Lead will generate code directly.",
            )

        # High-Complexity Swarm Decomposition
        decomposition_prompt = (
            f"Product ID: {product_id}\n"
            f"IaC Engine: {iac_engine}\n"
            f"VCS Provider: {vcs_provider}\n"
            f"Token Envelope Budget: {configured_envelope:,} tokens\n\n"
            f"Architecture Specification:\n{spec_text[:40000]}\n\n"
            f"Architecture Task DAG:\n{json.dumps(task_dag, indent=2)}\n\n"
            f"Active Enterprise Golden Modules in Platform:\n{json.dumps(golden_modules, indent=2)}\n\n"
            f"Decompose this specification into a phased, 3-wave Work Breakdown Structure adhering strictly "
            f"to the disjoint file partition invariant and the Zero-Dockerfiles mandate."
        )
        test_layout = lead_prompt_rule(service_names)
        if test_layout:
            decomposition_prompt = f"{decomposition_prompt}\n\n{test_layout}"
        if probe_rule:  # AC-2: topology_wiring.health_probe_rule (platform startup probe path); absent -> unchanged
            decomposition_prompt = f"{decomposition_prompt}\n\n{probe_rule}"
        if wiring_contract:  # lane 10 (FD-51): the topology contract for every junior task; absent -> unchanged
            decomposition_prompt = (f"{decomposition_prompt}\n\n{wiring_contract}\nCopy the relevant contract lines "
                                    f"into each junior task that writes a service's code or the custom IaC.")
        if iac_intent_rule:  # TI-3: typed IaC intent (mode "generate"); absent -> unchanged
            decomposition_prompt = f"{decomposition_prompt}\n\n{iac_intent_rule}"
        if app_auth_rule:  # DIRECT-IAP-SKILL-VERIFY: Direct IAP Cloud Run only; absent -> unchanged
            decomposition_prompt = f"{decomposition_prompt}\n\n{app_auth_rule}"
        base_decomposition_prompt = decomposition_prompt   # TI-3: a re-ask note replaces the previous one

        plan = None
        walk: Optional[CallWalk] = None
        self.last_model_provenance = None
        if self.genai_client:
            candidate_models = get_model_cascade_for_agent("developer", project_id=self.project_id)
            if self.model_name and self.model_name not in candidate_models:
                candidate_models.insert(0, self.model_name)
            # RT F3: the active stage deadline bounds the walk (direct callers too)
            deadline, stage_stop = active_stage_bound(deadline, stage_stop, self._clock)
            walk = CallWalk(candidate_models, purpose=CallPurpose.WBS, stage="developer", deadline=deadline,
                            stage_stop=stage_stop,   # RT F5: the active stage deadline's own stop class
                            clock=self._clock, abandoned=ledger_abandoned_sink(self.db, trace_id, "lead_developer"),
                            retry_last_on_transient=False)

            cooldown_attempt = 1
            max_cooldown_attempts = 3

            while not plan and cooldown_attempt <= max_cooldown_attempts:
                all_rate_limited = True
                last_rate_model = candidate_models[0] if candidate_models else "gemini"

                for m_name in list(candidate_models):
                    if not m_name:
                        continue
                    try:
                        from google.genai import types
                        logger.info(f"Invoking Lead Orchestrator model '{m_name}' for WBS decomposition...")
                        from shared.gemini_model_config import (Purpose, adapt_generate_config_kwargs,
                                                                max_output_tokens_for,
                                                                thinking_config_for)  # Argon compat 10-14
                        lead_kwargs = dict(
                            system_instruction=LEAD_ORCHESTRATOR_SYSTEM_PROMPT,
                            response_mime_type="application/json",
                            temperature=0.1,
                            max_output_tokens=max_output_tokens_for(m_name, developer_token_limit, Purpose.DEVELOPER),
                        )
                        # FD-4CI-b: the platform Thinking Budget (0: no thinking config, as before)
                        lead_tc = (thinking_config_for(m_name, thinking_budget, Purpose.DEVELOPER, types=types)
                                   if thinking_budget else None)
                        if lead_tc is not None:
                            lead_kwargs["thinking_config"] = lead_tc
                        # STAGE-DEADLINE checkpoint; the walk alone sets the call's http_options (RT F3)
                        stage_deadline.checkpoint("developer.lead_wbs")
                        call = walk.plan(m_name)   # SLOW-CALL-FALLBACK: bounded; no room left -> typed stop
                        outcome, call_err = None, None
                        for _try in (0, 1):   # RT F10: one same-model retry after 4 s on a 429 / 503
                            try:
                                response = self.genai_client.models.generate_content(
                                    model=m_name,
                                    contents=decomposition_prompt,
                                    config=walk.config(call, types.GenerateContentConfig(
                                        **adapt_generate_config_kwargs(m_name, Purpose.DEVELOPER, lead_kwargs,
                                                                       types=types))),
                                )
                                outcome = None
                                break
                            except stage_deadline.STOP_ERRORS:
                                raise
                            except Exception as e_call:
                                outcome, call_err = walk.failed(call, e_call), e_call
                                if outcome is None:
                                    raise   # not a typed timeout / transient: today's handling below
                                retry_s = walk.same_model_retry_s(call, outcome)
                                if retry_s is None:
                                    break
                                logger.warning(f"Lead model '{m_name}' {outcome}; retrying it once in {retry_s:.0f}s.")
                                self._sleep(retry_s)
                                stage_deadline.checkpoint("developer.lead_wbs")
                                call = walk.plan(m_name, backoff_s=retry_s)
                        if outcome is not None:
                            if outcome == TIMEOUT:
                                logger.warning(f"Lead model '{m_name}' timed out after "
                                               f"{walk.attempts[-1].elapsed_s:.1f}s; asking the next model.")
                                candidate_models = [cm for cm in candidate_models if cm != m_name]
                                all_rate_limited = False
                                continue
                            logger.warning(f"Lead model '{m_name}' hit transient Vertex AI error ({outcome}: "
                                           f"{call_err}). Cascading...")
                            last_rate_model = m_name
                            continue
                        if not walk.answered(call, response):
                            logger.warning(f"Lead model '{m_name}' answered after its timeout; the answer is not "
                                           f"used. Asking the next model.")
                            candidate_models = [cm for cm in candidate_models if cm != m_name]
                            all_rate_limited = False
                            continue
                        if trace_id and self.db:
                            try:
                                from shared.token_accounting import extract_token_usage, record_agent_tokens
                                usage_rec = extract_token_usage(response, m_name)
                                record_agent_tokens(self.db, trace_id, "lead_developer", usage_rec)
                            except Exception as t_err:
                                logger.debug(f"Failed to record lead developer tokens: {t_err}")

                        # Check for finish_reason MAX_TOKENS
                        if response and hasattr(response, "candidates") and response.candidates:
                            candidate = response.candidates[0]
                            finish_reason = getattr(candidate, "finish_reason", None)
                            if "MAX_TOKENS" in str(finish_reason).upper():
                                logger.critical(
                                    f"TOKEN_LIMIT_EXCEEDED: Lead model '{m_name}' reached output token limit ({developer_token_limit}). "
                                    f"Decomposition truncated. Cascading to next candidate."
                                )
                                candidate_models = [cm for cm in candidate_models if cm != m_name]
                                all_rate_limited = False
                                continue

                        if response and response.text:
                            raw_text = response.text.strip()
                            clean_json = re.sub(r"^```json\s*", "", raw_text)
                            clean_json = re.sub(r"\s*```$", "", clean_json)
                            try:
                                parsed = json.loads(clean_json)
                            except Exception as parse_err:
                                logger.warning(f"Lead model '{m_name}' output JSON decode failed: {parse_err}. Cascading...")
                                candidate_models = [cm for cm in candidate_models if cm != m_name]
                                all_rate_limited = False
                                continue

                            # Ensure engine, vcs, and envelope are stamped
                            parsed["iac_engine"] = iac_engine
                            parsed["vcs_provider"] = vcs_provider
                            if "max_swarm_token_envelope" not in parsed or not parsed["max_swarm_token_envelope"]:
                                parsed["max_swarm_token_envelope"] = configured_envelope
                            else:
                                parsed["max_swarm_token_envelope"] = min(int(parsed["max_swarm_token_envelope"]), configured_envelope)

                            plan = LeadDeveloperDecompositionPlan(**parsed)
                            hcl = iac_hcl_assignments(plan.tasks) if iac_intent_rule else []
                            # SCHEMAS-COLLISION: a plan may not own a Wave 0 registry file or a module a registry
                            # package shadows (exact path set; registry absent -> no registry files, no check)
                            reserved = (reserved_assignments(plan.tasks, product_id)
                                        if SharedContractRegistry and plan.tasks else [])
                            # TEST-LAYOUT-PLATFORM-FACT: with more than one typed service no task may own a file
                            # under the repository-root tests/ (QA's PY.TEST_LAYOUT, checked when the plan is made)
                            root_tests = root_test_assignments(plan.tasks, service_names)
                            if hcl or reserved or root_tests:
                                note = ""
                                if root_tests:
                                    logger.warning(f"Lead model '{m_name}' assigned root tests/ files {root_tests} in "
                                                   f"a multi-service workload; re-asking on the next model.")
                                    note += LEAD_TEST_LAYOUT_REASK.format(
                                        paths=json.dumps(sorted({p for _t, p in root_tests})))
                                if hcl:   # TI-3 (register TI-3b): no Terraform file is ever assigned on the intent path
                                    logger.warning(f"Lead model '{m_name}' assigned Terraform files {hcl} on the "
                                                   f"typed IaC intent path; re-asking on the next model.")
                                    note += LEAD_INTENT_REASK.format(paths=json.dumps(sorted({p for _t, p in hcl})))
                                if reserved:
                                    logger.warning(f"Lead model '{m_name}' assigned platform-owned Wave 0 schema "
                                                   f"paths {reserved}; re-asking on the next model.")
                                    note += LEAD_SCHEMAS_REASK.format(
                                        paths=json.dumps(sorted({p for _t, p in reserved})))
                                decomposition_prompt = base_decomposition_prompt + note
                                plan = None
                                candidate_models = [cm for cm in candidate_models if cm != m_name]
                                all_rate_limited = False
                                continue
                            self.last_model_provenance = {
                                "output": "wbs", "model": m_name, "primary_model": walk.primary,
                                "fallback": m_name != walk.primary,
                                "fallback_reason": walk.left_primary_reason() if m_name != walk.primary else None,
                                "attempts": [a.to_dict() for a in walk.attempts]}
                            logger.info(
                                f"Lead Orchestrator produced valid WBS plan with {len(plan.tasks)} tasks "
                                f"across {len(set(t.wave for t in plan.tasks))} waves via model '{m_name}' "
                                f"(budget envelope: {plan.max_swarm_token_envelope:,})."
                            )
                            all_rate_limited = False
                            stage_deadline.mark("developer.lead_wbs_done", model=m_name, tasks=len(plan.tasks))
                            break
                    except stage_deadline.STOP_ERRORS:
                        raise  # STAGE-DEADLINE: never cascade (or fall back to the deterministic plan) past a stop
                    except DeveloperStageError:
                        raise   # SLOW-CALL-FALLBACK: the stage budget is gone (typed), never a model to skip
                    except Exception as e:
                        if is_model_deprecated_error(e):
                            logger.warning(f"Lead model '{m_name}' is deprecated or not found (404). Pruning.")
                            candidate_models = [cm for cm in candidate_models if cm != m_name]
                            all_rate_limited = False
                            continue
                        elif is_transient_vertex_error(e):
                            logger.warning(f"Lead model '{m_name}' hit transient Vertex AI error (429 / 500 / Harpoon: {e}). Cascading...")
                            last_rate_model = m_name
                            continue
                        else:
                            logger.warning(f"Lead Orchestrator model '{m_name}' call failed: {e}. Trying next candidate...")
                            all_rate_limited = False

                if plan or not all_rate_limited:
                    break

                if all_rate_limited and not plan:
                    logger.warning(
                        f"All Lead Orchestrator candidate models ({candidate_models}) hit transient Vertex AI errors. "
                        f"Entering interruptible 60s cooldown (cycle {cooldown_attempt}/{max_cooldown_attempts})."
                    )
                    should_retry = wait_for_rate_limit_cooldown(
                        trace_id=trace_id or f"lead-{product_id}",
                        product_id=product_id,
                        stage="developer_lead_wbs_decomposition",
                        model_name=last_rate_model,
                        attempt=cooldown_attempt,
                        max_attempts=max_cooldown_attempts,
                        project_id=self.project_id,
                    )
                    if not should_retry:
                        break
                    cooldown_attempt += 1

        if not plan and walk is not None and walk.timed_out and not walk.any_answer:
            # SLOW-CALL-FALLBACK: no model answered in time -> typed stop with every attempt (invariant 8)
            raise walk.exhausted()
        if not plan:
            self.last_model_provenance = {"output": "wbs", "model": None, "deterministic": True,
                                          "attempts": [a.to_dict() for a in walk.attempts] if walk else []}
            plan = self._build_deterministic_fallback_plan(
                product_id=product_id,
                iac_engine=iac_engine,
                vcs_provider=vcs_provider,
                max_swarm_token_envelope=configured_envelope,
                service_names=service_names,
                **({"iac_intent": True} if iac_intent_rule else {}),   # TI-3
            )

        # Wave 0 Shared Contract Registry synthesis & task injection
        if SharedContractRegistry and plan.tasks:
            try:
                registry = SharedContractRegistry(product_id=product_id)
                wave_0_files = registry.extract_and_generate_contracts(
                    shared_contracts=plan.shared_contracts,
                    detected_services=plan_services(plan.tasks, product_id),
                    spec_text=spec_text,
                    assigned_files=[f for t in plan.tasks for f in t.assigned_files],   # SCHEMAS-COLLISION
                )
                plan.wave_0_contract_files = wave_0_files
                registry.inject_contracts_into_wbs_tasks(plan.tasks, wave_0_files)
                logger.info(
                    f"Successfully attached {len(wave_0_files)} Wave 0 contract files to WBS plan "
                    f"and injected read dependencies across {len(plan.tasks)} tasks."
                )
            except Exception as e:
                logger.warning(f"Wave 0 Shared Contract Registry processing encountered notice: {e}")

        return plan

    def _build_deterministic_fallback_plan(
        self,
        product_id: str,
        iac_engine: str,
        vcs_provider: str,
        max_swarm_token_envelope: int = 350_000,
        service_names: Optional[Iterable[str]] = None,
        iac_intent: bool = False,
    ) -> LeadDeveloperDecompositionPlan:
        """Constructs a deterministic, structurally verified 3-wave WBS fallback. TI-3: `iac_intent` (typed-intent
        mode) assigns the IaC task the typed intent instead of main/variables/outputs.tf; False = unchanged."""
        clean_pid = product_id.lower().replace("_", "-")
        # Row L3-PRB-t: the fallback's one generated service is apps/<clean_pid>; with more than one typed service its
        # tests go next to it (root tests/ next to several services is PY.TEST_LAYOUT in QA).
        tests_dir = service_tests_dir(clean_pid) if is_multi_service(service_names) else ROOT_TESTS_DIR
        tasks = [
            # Wave 1: Data models
            JuniorTaskAssignment(
                task_id=f"{clean_pid}-w1-db",
                persona=JuniorPersona.DATABASE_ENGINEER,
                wave=1,
                assigned_files=[f"apps/{clean_pid}/models.py", f"apps/{clean_pid}/db.py"],
                read_dependencies=[],
                task_objective="Implement Pydantic domain models and Firestore database client.",
                injected_contracts={},
                specific_guardrails=["Use Firestore async client with retry logic"],
                iac_engine=iac_engine,
            ),
            # Wave 2: Backend & IaC
            JuniorTaskAssignment(
                task_id=f"{clean_pid}-w2-backend",
                persona=JuniorPersona.BACKEND_ENGINEER,
                wave=2,
                assigned_files=[f"apps/{clean_pid}/main.py"],
                read_dependencies=[f"apps/{clean_pid}/models.py", f"apps/{clean_pid}/db.py"],
                task_objective="Implement FastAPI routing and core application business logic.",
                injected_contracts={},
                specific_guardrails=["Implement structured error responses and health check"],
                iac_engine=iac_engine,
            ),
            JuniorTaskAssignment(
                task_id=f"{clean_pid}-w2-iac",
                persona=JuniorPersona.IAC_ENGINEER,
                wave=2,
                assigned_files=([INTENT_PATH] if iac_intent else
                                ["infra/workload/main.tf", "infra/workload/variables.tf", "infra/workload/outputs.tf"]),
                read_dependencies=[],
                task_objective=("Write the typed IaC intent for the specification's infrastructure (golden modules "
                                "and allowed resources); realize every topology resource." if iac_intent else
                                "Assemble Cloud Run and Firestore infrastructure using golden modules."),
                injected_contracts={},
                specific_guardrails=(["No Terraform files: the platform renders all IaC from the intent"]
                                     if iac_intent else ["Zero public IPs, include startup and liveness probes"]),
                iac_engine=iac_engine,
            ),
            # Wave 3: QA & DevOps
            JuniorTaskAssignment(
                task_id=f"{clean_pid}-w3-qa",
                persona=JuniorPersona.TEST_ENGINEER,
                wave=3,
                assigned_files=[f"{tests_dir}/test_{clean_pid}.py", f"{tests_dir}/conftest.py"],
                read_dependencies=[f"apps/{clean_pid}/main.py", f"apps/{clean_pid}/models.py"],
                task_objective="Implement pytest test suite covering API endpoints and error conditions.",
                injected_contracts={},
                specific_guardrails=["Mock all GCP Firestore calls"],
                iac_engine=iac_engine,
            ),
            JuniorTaskAssignment(
                task_id=f"{clean_pid}-w3-devops",
                persona=JuniorPersona.DEVOPS_ENGINEER,
                wave=3,
                assigned_files=["Procfile", "requirements.txt", ".gcloudignore", "cloudbuild.yaml"],
                read_dependencies=[f"apps/{clean_pid}/main.py"],
                task_objective="Create Google Cloud Buildpacks entrypoint, requirements, and Cloud Build triggers.",
                injected_contracts={},
                specific_guardrails=["Strictly ZERO Dockerfiles allowed"],
                iac_engine=iac_engine,
            ),
        ]

        return LeadDeveloperDecompositionPlan(
            execution_mode=SwarmExecutionMode.STANDARD_SWARM,
            iac_engine=iac_engine,
            vcs_provider=vcs_provider,
            max_swarm_token_envelope=max_swarm_token_envelope,
            shared_contracts={},
            tasks=tasks,
            lead_notes="Standard 3-wave deterministic fallback plan generated.",
        )
