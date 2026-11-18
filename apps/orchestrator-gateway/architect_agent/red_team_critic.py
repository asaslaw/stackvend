"""
Project Castor: Principal Red-Team Reviewer (Architect 2)
Performs hypercritical adversarial audits across the 5-Point Invariant Gauntlet,
grounded against the golden-module catalog derived from the built-in module payload
(CANONICAL_GOLDEN_MODULES) and deterministic cycle detection.
"""

import json
import logging
import os  # FD-4BO scan: used by the get_model_cascade_for_agent import fallback below
import re
from typing import Any, Dict, List, Optional

try:
    from shared.critic_schemas import (
        ArchitecturalCritique,
        CritiqueCategory,
        CritiqueFinding,
        CritiqueSeverity,
        GauntletCheckResult,
    )
except ImportError:
    from .critic_schemas import (
        ArchitecturalCritique,
        CritiqueCategory,
        CritiqueFinding,
        CritiqueSeverity,
        GauntletCheckResult,
    )

try:
    from shared.builtin_prompts import (
        ARCHITECT_RED_TEAM_CRITIC_PROMPT,
        get_builtin_prompt,
    )
except ImportError:
    from builtin_prompts import (
        ARCHITECT_RED_TEAM_CRITIC_PROMPT,
        get_builtin_prompt,
    )

from .cycle_detector import validate_dual_layer_dag

import stage_deadline   # STAGE-DEADLINE (gateway root module); module level so every `except` below can name it

logger = logging.getLogger("castor-red-team-critic")

try:
    from shared.settings import get_model_cascade_for_agent
except ImportError:
    try:
        from ..shared.settings import get_model_cascade_for_agent
    except ImportError:
        def get_model_cascade_for_agent(agent_name, project_id=None):
            return [os.getenv("GEMINI_MODEL") or "gemini-4-carbon", "gemini-4-argon"]

try:  # Argon compat (owner 10-14): per-model-family request rules; identity for Gemini <= 3.x
    from shared.gemini_model_config import Purpose, adapt_generate_config_kwargs, max_output_tokens_for
except ImportError:  # pragma: no cover
    from ..shared.gemini_model_config import (Purpose, adapt_generate_config_kwargs,  # type: ignore
                                              max_output_tokens_for)

try:  # FD-4AM-c: the golden-module set the developer stage vends (== infra/modules: tests/test_lane8_payload_parity.py)
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES as _BUILTIN_MODULE_FILES
except ImportError:  # no silent empty fallback: an empty catalog would make the critic flag every module
    from ..shared.builtin_modules_payload import BUILTIN_MODULE_FILES as _BUILTIN_MODULE_FILES  # type: ignore

# Golden modules only the host platform uses, never a workload: `workflows` (the host's own
# orchestrator / SRE workflows; FD-4AM-d, FD-4CB-b). One source of truth for the critic, the developer stage and the
# typed-IaC catalog: shared/host_platform_modules.py. (`workflows-dag` is a separate workload module and stays offered.)
try:
    from shared.host_platform_modules import HOST_PLATFORM_ONLY_MODULES
except ImportError:  # pragma: no cover
    from ..shared.host_platform_modules import HOST_PLATFORM_ONLY_MODULES  # type: ignore

# The golden modules a workload plan may use, as given to the critic LLM: every built-in module payload key except the
# host-platform-only ones, sorted so the critic prompt is deterministic. tests/test_fd4am_critic_catalog.py pins that
# every entry is a real infra/modules directory and that every payload key is either offered or explicitly excluded.
# FD-4BH: golden modules only the platform's own render calls (the typed-intent VPC connector, module.stackvend_connector
# in shared/iac_intent.py). A plan never names them, so they are not offered either; the critic prompt stays as before.
PLATFORM_RENDERED_MODULES = frozenset({"networking-vpc-connector"})
CANONICAL_GOLDEN_MODULES: List[str] = sorted(set(_BUILTIN_MODULE_FILES) - HOST_PLATFORM_ONLY_MODULES
                                             - PLATFORM_RENDERED_MODULES)

# Prefix of every gauntlet item the deterministic fallback (LLM critic unavailable or failed) does not check
# (FD-4AM-c grounding; FD-4AM-d IAM, spec coverage, FinOps): such an item is a WARNING with this text, never PASSED.
FALLBACK_NOT_CHECKED = "Not checked (LLM critic unavailable)"


class RedTeamCritic:
    """
    Adversarial reviewer evaluating Architect 1's draft plan against
    the 5-Point Invariant Gauntlet.
    """

    def __init__(
        self,
        genai_client: Any = None,
        model_name: str = "gemini-3.8-flash",
    ):
        self.genai_client = genai_client
        self.model_name = model_name
        self.last_audit_used_llm = False

    def audit_plan(
        self,
        plan: Any,
        spec_text: str,
        policy_matrix: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None,
        db: Any = None,
        context: Any = None,
    ) -> ArchitecturalCritique:
        """
        Executes Kahn's algorithm cycle check followed by adversarial LLM audit.

        `context` (RT14-16): the run's ArchitectContext; the critic is told the operator's REWORK guidance so a plan
        that follows it is not flagged as having dropped a specification directive.
        """
        # Extract steps and tasks
        steps = []
        build_plan = getattr(plan, "sequenced_build_plan", None)
        if build_plan:
            steps = getattr(build_plan, "steps", []) or []

        infra_tasks = getattr(plan, "infra_tasks", []) or []
        code_tasks = getattr(plan, "code_tasks", []) or []

        # 1. Deterministic Cycle & Topology Detection
        topo_result = validate_dual_layer_dag(
            steps=steps,
            infra_tasks=infra_tasks,
            code_tasks=code_tasks,
        )

        critical_findings: List[CritiqueFinding] = []
        gauntlet_results: Dict[str, GauntletCheckResult] = {}

        if not topo_result.is_valid:
            for err in topo_result.errors:
                critical_findings.append(
                    CritiqueFinding(
                        category=CritiqueCategory.TOPOLOGY_AND_ORDERING,
                        severity=CritiqueSeverity.CRITICAL,
                        step_or_task_id=None,
                        description=f"Topological defect: {err}",
                        recommended_remediation="Resolve dependency cycle or missing prerequisite step to restore topological order.",
                    )
                )
            gauntlet_results["DAG Topology & Cycles"] = GauntletCheckResult(
                invariant_name="DAG Topology & Cycles",
                status="CRITICAL",
                details=f"Kahn's algorithm detected violations: {'; '.join(topo_result.errors[:2])}",
            )
        else:
            gauntlet_results["DAG Topology & Cycles"] = GauntletCheckResult(
                invariant_name="DAG Topology & Cycles",
                status="PASSED",
                details="Kahn's algorithm verified: 0 cycles, 0 orphan dependencies.",
            )

        # 2. Invoke Gemini for Deep Adversarial Audit (if client available)
        llm_critique = self._invoke_llm_critic(plan, spec_text, topo_result, policy_matrix, trace_id=trace_id, db=db,
                                               context=context)
        # RT14-06: whether this audit's verdict includes the LLM checks (the consensus engine claims a remediation
        # resolved an LLM finding only when the re-audit ran the LLM critic too).
        self.last_audit_used_llm = llm_critique is not None

        if llm_critique:
            # Merge deterministic findings with LLM findings
            all_findings = critical_findings + llm_critique.findings
            has_crit = any(f.severity == CritiqueSeverity.CRITICAL for f in all_findings)

            # Ensure all 5 gauntlet checks are populated
            final_checks = []
            for check in llm_critique.gauntlet_checks:
                if check.invariant_name == "DAG Topology & Cycles" and not topo_result.is_valid:
                    final_checks.append(gauntlet_results["DAG Topology & Cycles"])
                else:
                    final_checks.append(check)

            if "DAG Topology & Cycles" not in {c.invariant_name for c in final_checks}:
                final_checks.insert(0, gauntlet_results["DAG Topology & Cycles"])

            score = min(llm_critique.soundness_score, 0.4 if not topo_result.is_valid else 1.0)
            verdict = llm_critique.verdict_summary
            if not topo_result.is_valid and "critical" not in verdict.lower():
                verdict = f"REJECTED: Topological cycle detected. {verdict}"

            return ArchitecturalCritique(
                soundness_score=score,
                has_critical_findings=has_crit,
                findings=all_findings,
                gauntlet_checks=final_checks,
                verdict_summary=verdict,
            )

        # 3. Fallback Critique when LLM is unavailable
        return self._deterministic_fallback_critique(topo_result, critical_findings, gauntlet_results)

    def _invoke_llm_critic(
        self,
        plan: Any,
        spec_text: str,
        topo_result: Any,
        policy_matrix: Optional[Dict[str, Any]],
        trace_id: Optional[str] = None,
        db: Any = None,
        context: Any = None,
    ) -> Optional[ArchitecturalCritique]:
        """Calls Gemini using structured output to evaluate the 5-point gauntlet.

        ``trace_id`` / ``db`` come from ``audit_plan`` (FD-4AH: they were referenced here but never passed) and are
        used only for token accounting.
        """
        if not self.genai_client:
            return None

        try:
            # Format plan as serialized JSON
            if hasattr(plan, "model_dump_json"):
                plan_json = plan.model_dump_json(indent=2)
            elif hasattr(plan, "dict"):
                plan_json = json.dumps(plan.dict(), indent=2, default=str)
            else:
                plan_json = json.dumps(plan, indent=2, default=str)

            critic_prompt = get_builtin_prompt("ARCHITECT_RED_TEAM_CRITIC") or ARCHITECT_RED_TEAM_CRITIC_PROMPT

            user_content = (
                f"### CANONICAL GOLDEN MODULES CATALOG (ALLOWED PLATFORM MODULES):\n"
                f"{json.dumps(CANONICAL_GOLDEN_MODULES, indent=2)}\n\n"
                f"### ORIGINAL USER SPECIFICATION:\n{spec_text}\n\n"
                f"### PROPOSED ARCHITECTURE PLAN & TASK DAG:\n{plan_json}\n\n"
                f"### DETERMINISTIC TOPOLOGICAL VALIDATION RESULT:\n"
                f"Valid: {topo_result.is_valid} | Cycles: {topo_result.cycle_detected} | "
                f"Orphans: {topo_result.orphan_dependencies} | Violations: {topo_result.ordering_violations}\n"
            )

            if policy_matrix:
                user_content += f"\n### ACTIVE GCP ORGANIZATION POLICIES:\n{json.dumps(policy_matrix, indent=2)}\n"
            if context is not None and hasattr(context, "critic_blocks"):
                user_content += context.critic_blocks()   # RT14-16: "" without operator feedback (prompt unchanged)

            user_content += (
                "\nPerform your hypercritical 5-Point Invariant Gauntlet audit. "
                "Classify any missing prerequisite steps, dropped directives, or module hallucinations as CRITICAL. "
                "Respond strictly with the ArchitecturalCritique schema."
            )

            models_to_try = get_model_cascade_for_agent("architect")
            # DEFAULT-FALLBACK-CHAIN: the critic's model (ARCHITECT_CRITIC_MODEL) leads even when it is also a fallback
            if self.model_name:
                models_to_try = [self.model_name] + [m for m in models_to_try if m != self.model_name]
            token_limit = 65536
            try:
                from shared.settings import get_platform_settings
                settings = get_platform_settings()
                token_limit = settings.models.get_architect_token_limit()
            except Exception:
                token_limit = 65536

            from google.genai import types as genai_types  # Argon compat: injected into the request rules
            for m_name in models_to_try:
                # STAGE-DEADLINE: checkpoint outside the per-model try; the outer `except` re-raises it (RT14-24)
                stage_deadline.checkpoint("architect.red_team")
                try:
                    response = self.genai_client.models.generate_content(
                        model=m_name,
                        contents=user_content,
                        config=stage_deadline.bound_llm_config(adapt_generate_config_kwargs(m_name, Purpose.ARCHITECT, {
                            "system_instruction": critic_prompt,
                            "response_mime_type": "application/json",
                            "response_schema": ArchitecturalCritique,
                            "temperature": 0.1,
                            "max_output_tokens": max_output_tokens_for(m_name, token_limit, Purpose.ARCHITECT),
                        }, types=genai_types), "architect.red_team", types=genai_types),
                    )

                    # Token Accounting: Extract and record critic tokens
                    try:
                        from shared.token_accounting import extract_token_usage, record_agent_tokens
                        usage_rec = extract_token_usage(response, model_name=m_name)
                        if usage_rec:
                            self.last_critic_tokens = usage_rec
                            if trace_id:
                                # Same client rule as the architect's own token accounting (handler.py): the
                                # caller's db, else a client for the gateway's PROJECT_ID; no project -> no write.
                                fs_db = db
                                if fs_db is None and os.getenv("PROJECT_ID"):
                                    from google.cloud import firestore
                                    fs_db = firestore.Client(project=os.getenv("PROJECT_ID"))
                                if fs_db is not None:
                                    record_agent_tokens(fs_db, trace_id, "red_team_critic", usage_rec)
                    except Exception as tok_err:
                        logger.debug(f"Critic token accounting notice: {tok_err}")

                    if response and hasattr(response, "candidates") and response.candidates:
                        candidate = response.candidates[0]
                        finish_reason = getattr(candidate, "finish_reason", None)
                        if "MAX_TOKENS" in str(finish_reason).upper():
                            logger.warning(
                                f"TOKEN_LIMIT_EXCEEDED: Critic model '{m_name}' reached max_output_tokens ({token_limit}). Cascading..."
                            )
                            continue

                    if response and response.text:
                        data = json.loads(response.text.strip())
                        return ArchitecturalCritique(**data)
                except stage_deadline.STOP_ERRORS:
                    raise  # RT14-24: a stopped stage is never a critic error (bound_llm_config checkpoints here)
                except Exception as m_err:
                    logger.debug(f"Critic call failed on model {m_name}: {m_err}")

        except stage_deadline.STOP_ERRORS:
            raise  # RT14-24: never swallowed into the deterministic fallback (which answers CONSENSUS_VERIFIED)
        except Exception as e:
            logger.warning(f"Failed to execute LLM critic audit: {e}")

        return None

    def _deterministic_fallback_critique(
        self,
        topo_result: Any,
        critical_findings: List[CritiqueFinding],
        gauntlet_results: Dict[str, GauntletCheckResult],
    ) -> ArchitecturalCritique:
        """Deterministic fallback when Gemini client is not initialized."""
        checks = [
            gauntlet_results.get(
                "DAG Topology & Cycles",
                GauntletCheckResult(
                    invariant_name="DAG Topology & Cycles",
                    status="PASSED" if topo_result.is_valid else "CRITICAL",
                    details="Deterministic Kahn's algorithm evaluation",
                ),
            ),
            # FD-4AM-c (grounding) / FD-4AM-d (IAM, spec coverage, FinOps): only the DAG check above runs without the
            # LLM critic. Nothing here checks the four items below, so each is the advisory WARNING "Not checked
            # (...)", never PASSED. None of them blocks a plan: blocking is has_critical_findings, which they do not set.
            GauntletCheckResult(
                invariant_name="IAM & Security Sequencing",
                status="WARNING",
                details=f"{FALLBACK_NOT_CHECKED}: no deterministic check of IAM / service-account ordering in the plan",
            ),
            GauntletCheckResult(
                invariant_name="Golden Modules Grounding",
                status="WARNING",
                details=f"{FALLBACK_NOT_CHECKED}: the plan has no typed module-id field to check "
                        "deterministically against the golden-module catalog",
            ),
            GauntletCheckResult(
                invariant_name="User Specification Coverage",
                status="WARNING",
                details=f"{FALLBACK_NOT_CHECKED}: no deterministic check that every specification requirement "
                        "maps to a task",
            ),
            GauntletCheckResult(
                invariant_name="FinOps & Anti-Bloat Sizing Sanity",
                status="WARNING",
                details=f"{FALLBACK_NOT_CHECKED}: no sizing review here (the FinOps cost check stage prices the "
                        "plan separately)",
            ),
        ]

        has_crit = not topo_result.is_valid
        score = 0.5 if has_crit else 1.0
        verdict = (
            "CRITICAL: Topological violations detected by Kahn's algorithm."
            if has_crit
            else "Plan passed deterministic topological validation (offline mode)."
        )

        return ArchitecturalCritique(
            soundness_score=score,
            has_critical_findings=has_crit,
            findings=critical_findings,
            gauntlet_checks=checks,
            verdict_summary=verdict,
        )
