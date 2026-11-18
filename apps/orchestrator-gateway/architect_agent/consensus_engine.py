"""
Project Castor: Bounded Dual-Architect Consensus Engine
Coordinates adversarial audit, fast-pass verification, and bounded N=1 remediation
turns with circuit breaker fault tolerance.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    from shared.critic_schemas import (
        ArchitecturalCritique,
        ArchitectSubagentTelemetry,
        CritiqueSeverity,
        DualArchitectConsensusTelemetry,
    )
except ImportError:
    from .critic_schemas import (
        ArchitecturalCritique,
        ArchitectSubagentTelemetry,
        CritiqueSeverity,
        DualArchitectConsensusTelemetry,
    )

import stage_deadline   # STAGE-DEADLINE (gateway root module)

from .red_team_critic import RedTeamCritic
from .context import DECOMPOSITION_PATH_MAP_REDUCE, ArchitectContext

logger = logging.getLogger("castor-architect-consensus")


class DualArchitectConsensusEngine:
    """
    Orchestrates the Generator-Critic consensus protocol:
    1. Critic audits draft plan.
    2. Fast pass if 0 critical findings (<2s).
    3. Single-pass targeted remediation (N=1) if critical findings exist.
    4. Fault-tolerant circuit breaker prevents pipeline aborts on model errors.
    """

    def __init__(
        self,
        critic: Optional[RedTeamCritic] = None,
        genai_client: Any = None,
        model_name: str = "gemini-3.7-flash",
    ):
        self.genai_client = genai_client
        self.model_name = model_name
        self.critic = critic or RedTeamCritic(genai_client=genai_client, model_name=model_name)

    def evaluate_and_reconcile(
        self,
        plan: Any,
        spec_text: str,
        architect_agent: Any,
        product_id: str,
        trace_id: str,
        policy_matrix: Optional[Dict[str, Any]] = None,
        context: Optional[ArchitectContext] = None,
    ) -> Tuple[Any, DualArchitectConsensusTelemetry]:
        """
        Executes consensus gauntlet. Returns (reconciled_plan, telemetry).

        `context` (RT14-06): the run's ArchitectContext (the architect passes the one it built); without it, a context
        of `policy_matrix` alone (direct callers, as before).
        """
        ctx = context if context is not None else ArchitectContext(policy_matrix=policy_matrix)
        policy_matrix = ctx.policy_matrix
        subagents: List[ArchitectSubagentTelemetry] = []

        # 1. Lead Architect synthesis telemetry (already completed prior to this call)
        lead_tokens = getattr(architect_agent, "last_architect_tokens", None)
        lead_output_toks = getattr(lead_tokens, "candidates_tokens", 2500) or 2500
        subagents.append(
            ArchitectSubagentTelemetry(
                persona="LEAD_ARCHITECT",
                status="SUCCEEDED",
                elapsed_seconds=0.0,
                output_tokens=lead_output_toks,
            )
        )

        # Synchronize client with architect_agent (honors test mocks and offline mode)
        if hasattr(architect_agent, "genai_client"):
            self.critic.genai_client = architect_agent.genai_client

        # 2. Red-Team Critic Audit
        t0 = time.time()
        critique: ArchitecturalCritique = self.critic.audit_plan(
            plan=plan,
            spec_text=spec_text,
            policy_matrix=policy_matrix,
            trace_id=trace_id,
            db=getattr(architect_agent, "db", None),
            context=ctx,   # RT14-16: the operator's REWORK guidance is not a "dropped directive"
        )
        t_critic = time.time() - t0
        critic_tokens = getattr(self.critic, "last_critic_tokens", None)
        critic_output_toks = getattr(critic_tokens, "candidates_tokens", 800) or 800

        subagents.append(
            ArchitectSubagentTelemetry(
                persona="RED_TEAM_CRITIC",
                status="SUCCEEDED" if not critique.has_critical_findings else "FAILED",
                elapsed_seconds=round(t_critic, 2),
                output_tokens=critic_output_toks,
            )
        )

        # 3. Fast-Pass Branch: 0 critical faults
        if not critique.has_critical_findings:
            logger.info(f"Consensus FAST-PASS verified for '{product_id}' (Score: {critique.soundness_score})")
            telemetry = DualArchitectConsensusTelemetry(
                consensus_status="CONSENSUS_VERIFIED",
                soundness_score=critique.soundness_score,
                has_critical_findings=False,
                remediation_performed=False,
                remediation_diff_summary=None,
                subagents=subagents,
                gauntlet_checks=critique.gauntlet_checks,
                findings=critique.findings,
            )
            return plan, telemetry

        # 4a. RT14-06: a plan PRODUCED by the map-reduce path is never "remediated" by re-running map-reduce (it
        #     re-plans every chunk from the raw text, cannot patch a draft, and used to report the faults Resolved).
        #     RT F3: read the typed path the architect recorded for this plan, never re-derived from the spec text (a
        #     map-reduce failure falls back to single-turn, whose draft the remediation turn CAN patch).
        if getattr(architect_agent, "last_decomposition_path", None) == DECOMPOSITION_PATH_MAP_REDUCE:
            n_crit = len([f for f in critique.findings if f.severity == CritiqueSeverity.CRITICAL])
            logger.critical(f"ARCHITECT_REMEDIATION_SKIPPED for '{product_id}': {n_crit} critical finding(s) on a "
                            f"map-reduce plan; keeping the draft as CRITIQUE_FAILED (no remediation turn).")
            telemetry = DualArchitectConsensusTelemetry(
                consensus_status="CRITIQUE_FAILED",
                soundness_score=critique.soundness_score,
                has_critical_findings=True,
                remediation_performed=False,
                remediation_diff_summary=(
                    f"Remediation not attempted: the specification uses the chunked map-reduce path, which cannot "
                    f"patch a draft plan. {n_crit} critical finding(s) remain for review."),
                subagents=subagents,
                gauntlet_checks=critique.gauntlet_checks,
                findings=critique.findings,
            )
            return plan, telemetry

        # 4. Bounded Remediation Branch (N=1)
        logger.warning(
            f"Consensus critical findings detected for '{product_id}': "
            f"{len([f for f in critique.findings if f.severity == CritiqueSeverity.CRITICAL])} faults. "
            f"Executing bounded N=1 remediation turn."
        )

        t_rem_start = time.time()
        first_audit_used_llm = bool(getattr(self.critic, "last_audit_used_llm", False))
        try:
            patched_plan, diff_summary = self._execute_remediation_turn(
                plan=plan,
                critique=critique,
                spec_text=spec_text,
                architect_agent=architect_agent,
                product_id=product_id,
                trace_id=trace_id,
                context=ctx,
            )
            t_rem = time.time() - t_rem_start

            subagents.append(
                ArchitectSubagentTelemetry(
                    persona="REMEDIATION_TURN",
                    status="SUCCEEDED",
                    elapsed_seconds=round(t_rem, 2),
                    output_tokens=2000,
                )
            )

            # RT14-06: the critic re-audits the patched plan (its checks include the DAG re-validation that used to be
            # the only check here). AUTO_REMEDIATED / "Resolved" only when the re-audit has no critical finding AND
            # could check what the first audit checked (an LLM finding needs an LLM re-audit); the score is the
            # re-audit's, never a hardcoded 0.95.
            t_re = time.time()
            recheck: ArchitecturalCritique = self.critic.audit_plan(
                plan=patched_plan,
                spec_text=spec_text,
                policy_matrix=policy_matrix,
                trace_id=trace_id,
                db=getattr(architect_agent, "db", None),
                context=ctx,
            )
            re_audit_used_llm = bool(getattr(self.critic, "last_audit_used_llm", False))
            subagents.append(
                ArchitectSubagentTelemetry(
                    persona="RED_TEAM_CRITIC",
                    status="SUCCEEDED" if not recheck.has_critical_findings else "FAILED",
                    elapsed_seconds=round(time.time() - t_re, 2),
                    output_tokens=getattr(getattr(self.critic, "last_critic_tokens", None), "candidates_tokens", 0) or 0,
                )
            )
            n_fixed = len([f for f in critique.findings if f.severity == CritiqueSeverity.CRITICAL])
            remaining = [f for f in recheck.findings if f.severity == CritiqueSeverity.CRITICAL]
            verified = re_audit_used_llm or not first_audit_used_llm   # an LLM finding needs an LLM re-audit
            if recheck.has_critical_findings:
                final_status, has_crit = "CRITIQUE_FAILED", True
                diff_summary = (f"{diff_summary} Re-audit of the patched plan: {len(remaining)} critical finding(s) "
                                f"remain" + (f" ({remaining[0].description[:80]})" if remaining else "") + ".")
            elif not verified:
                final_status, has_crit = "CRITIQUE_FAILED", True
                diff_summary = (f"{diff_summary} Not verified: the LLM critic could not re-audit the patched plan, so "
                                f"the {n_fixed} critical finding(s) are not confirmed resolved.")
            else:
                final_status, has_crit = "AUTO_REMEDIATED", False
                first = next((f for f in critique.findings if f.severity == CritiqueSeverity.CRITICAL), None)
                diff_summary = (f"{diff_summary} Re-audit of the patched plan found no critical finding."
                                + (f" Resolved: {first.description[:80]}" if first else ""))

            telemetry = DualArchitectConsensusTelemetry(
                consensus_status=final_status,
                soundness_score=recheck.soundness_score,
                has_critical_findings=has_crit,
                remediation_performed=True,
                remediation_diff_summary=diff_summary,
                subagents=subagents,
                gauntlet_checks=recheck.gauntlet_checks,
                findings=critique.findings + [f for f in recheck.findings if f.severity == CritiqueSeverity.CRITICAL],
            )
            return patched_plan, telemetry

        except stage_deadline.STOP_ERRORS:
            raise  # RT14-24: a stopped stage is not a failed remediation turn (never CRITIQUE_FAILED + the draft)
        except Exception as e:
            # Fault-tolerant circuit breaker
            logger.critical(f"ARCHITECT_REMEDIATION_FAILED for '{product_id}': {e}. Preserving draft plan.")
            subagents.append(
                ArchitectSubagentTelemetry(
                    persona="REMEDIATION_TURN",
                    status="FAILED",
                    elapsed_seconds=round(time.time() - t_rem_start, 2),
                    output_tokens=0,
                )
            )
            telemetry = DualArchitectConsensusTelemetry(
                consensus_status="CRITIQUE_FAILED",
                soundness_score=critique.soundness_score,
                has_critical_findings=True,
                remediation_performed=False,
                remediation_diff_summary=f"Remediation turn failed: {str(e)}",
                subagents=subagents,
                gauntlet_checks=critique.gauntlet_checks,
                findings=critique.findings,
            )
            return plan, telemetry

    @staticmethod
    def _draft_compute_decision(plan: Any) -> str:
        """Owner Q-B (10-13, example 05): the remediation turn re-decomposes the whole plan and once flipped a
        correct gke-autopilot draft to cloudrun. The brief now states the draft's typed compute decision and asks to
        keep it unless a listed fault is about compute (a prompt rule; the topology gate still validates the result)."""
        topo = getattr(plan, "_raw_service_topology", None)
        if topo is None:
            typed = getattr(plan, "service_topology", None)
            topo = typed.model_dump(mode="json") if hasattr(typed, "model_dump") else typed
        decision = {"compute_archetype": getattr(plan, "compute_archetype", None), "service_topology": topo}
        try:
            text = json.dumps(decision, sort_keys=True, default=str)
        except Exception:  # noqa: BLE001 - test doubles
            return ""
        return (
            "\n\n--- TYPED COMPUTE DECISION OF THE DRAFT ---\n"
            f"{text}\n"
            "Return this same compute_archetype and service_topology (services, kinds, primary_service, edges, "
            "resources, pushes) unless a critical fault above is explicitly about which compute services exist or "
            "what kind they are. Never change a service's kind to fix an ordering, coverage, IAM or sizing fault.\n"
            "--- END TYPED COMPUTE DECISION ---"
        )

    @staticmethod
    def _draft_plan_json(plan: Any, subject: Optional[str] = None) -> str:
        """RT14-16: the draft plan's typed JSON (tasks, build plan, topology; not the rendered markdown), so the
        remediation turn patches the draft rather than re-planning from the specification.

        PLAN-CONTRACT-CHECK (RT 13): `subject` names the block above that the draft is sent back for (the plan
        contract re-plan passes "the platform plan contract above"). None keeps the consensus critique's text
        byte-identical."""
        try:
            if hasattr(plan, "model_dump"):
                text = json.dumps(plan.model_dump(mode="json", exclude={"plan_markdown", "plan_file_path"}),
                                  sort_keys=True, default=str)
            else:
                text = json.dumps(plan, sort_keys=True, default=str)
        except Exception:  # noqa: BLE001 - test doubles
            return ""
        if subject is None:
            about, changes = "the critique", "the critical faults above require"
        else:
            about, changes = subject, f"{subject} requires"
        return (
            f"\n\n--- DRAFT PLAN (typed JSON of the plan {about} is about) ---\n"
            f"{text}\n"
            f"Return this plan with only the changes {changes}; keep every other task, step, "
            "service and resource as it is.\n"
            "--- END DRAFT PLAN ---"
        )

    def _execute_remediation_turn(
        self,
        plan: Any,
        critique: ArchitecturalCritique,
        spec_text: str,
        architect_agent: Any,
        product_id: str,
        trace_id: str,
        context: Optional[ArchitectContext] = None,
    ) -> Tuple[Any, str]:
        """
        Prompts Architect 1 to perform a targeted patch satisfying the critique.

        RT14-16: the turn gets the run's whole context, unchanged (organization policies, the operator's REWORK
        guidance, the quota snapshot), and the critique goes in its own block AFTER the operator's guidance, never in
        its place; the brief carries the draft plan's typed JSON so the turn patches it instead of re-planning from
        the raw specification (which put back what the operator had removed).
        """
        ctx = context if context is not None else ArchitectContext()
        critical_faults = [f for f in critique.findings if f.severity == CritiqueSeverity.CRITICAL]
        faults_bulleted = "\n".join(
            [f"- [{f.category.value}] {f.description} -> Fix: {f.recommended_remediation}" for f in critical_faults]
        )

        patch_brief = (
            f"--- ADVERSARIAL RED-TEAM ARCHITECTURAL AUDIT (CRITICAL FAULTS DETECTED) ---\n"
            f"The Principal Red-Team Reviewer rejected the draft DAG due to the following critical defects:\n"
            f"{faults_bulleted}\n\n"
            f"MANDATE: Perform a single-pass targeted patch. Fix the missing dependencies, stage order, or dropped "
            f"directives while preserving the valid parts of the plan. Ensure 100% topological validity.\n"
            + ("The operator's REWORK guidance above takes precedence over this critique: never re-add what the "
               "operator removed and never undo what the operator changed.\n" if ctx.operator_feedback else "")
            + "--- END CRITIQUE ---"
        ) + self._draft_plan_json(plan) + self._draft_compute_decision(plan)

        # Re-invoke decomposition with remediation feedback. topology_gate=False: the OUTER decompose gates and
        # persists the final plan's service topology (lane 10), so this intermediate plan is never recorded.
        patched_result = architect_agent.decompose(
            spec_text=spec_text,
            product_id=product_id,
            trace_id=trace_id,
            policy_matrix=ctx.policy_matrix,
            human_feedback=ctx.human_feedback,      # the operator's own words, still labelled as the operator's
            quota_snapshot=ctx.quota_snapshot,
            remediation_brief=patch_brief,          # the critique, after the operator's guidance
            bypass_consensus=True,  # Crucial: Prevent infinite recursion!
            topology_gate=False,
        )

        patched_plan = getattr(patched_result, "architecture_plan", patched_result)
        # RT14-06: what the turn did, never a claim that it worked ("Resolved" is written only after the re-audit).
        diff_summary = f"Remediation turn patched the plan for {len(critical_faults)} critical architectural defect(s)."

        return patched_plan, diff_summary
