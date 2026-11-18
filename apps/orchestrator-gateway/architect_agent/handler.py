"""
Project Castor: Architect Agent Execution Handler
Invokes Vertex AI Gemini to decompose specifications into actionable Task DAGs.
"""

import json
import logging
import os
import runtime_env  # G1: on_cloud_run() = service or stage-runner job (never K_SERVICE alone)
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

try:
    import httpx  # FD-4AH: used by the Google-Doc spec fetch and checklist append (was never imported)
except ImportError:  # pragma: no cover - httpx is in requirements.txt; without it both calls keep their fallbacks
    httpx = None

from gate_errors import GateError, GateUnavailableError, OperatorActionRequiredError
import stage_deadline   # STAGE-DEADLINE (gateway root module)

# RT14-30: the fields of pipeline_executions/{trace}/stage_traces/architect that the architect writes (each replaced
# on every write; an absent optional one is removed). PLAN-CONTRACT-CHECK adds `plan_contract`.
ARCHITECT_STAGE_TRACE_FIELDS = ("trace_id", "stage_name", "rendered_prompt", "agent_output", "created_at",
                                "is_few_shot_candidate", "topology_error", "test_layout_changes", "architect_consensus",
                                "plan_contract")

# PLAN-CONTRACT-CHECK §3.3 (RT 13): the re-plan brief's draft renderer names the contract, not "the critique".
PLAN_CONTRACT_DRAFT_SUBJECT = "the platform plan contract above"
# §3.3 swap step 4: the consensus telemetry describes the audited draft; this states what happened after it.
PLAN_CONTRACT_TELEMETRY_NOTE = ("Re-planned after consensus for the platform plan contract; the re-plan was not "
                                "re-audited by the critic.")
# The agent attributes a re-plan's inner decompose overwrites; restored to the draft's values when the draft is kept
# (strip, refusal, outage), so the stage trace never shows a refused re-plan as the architect's output.
_PLAN_CONTRACT_DRAFT_ATTRS = ("last_architect_raw_output", "last_architect_rendered_prompt",
                              "last_build_plan_from_model", "last_decomposition_path", "last_test_layout_changes")

# HTTP timeout of the Google-Doc checklist append (RT14-24: the append starts only with this much stage budget left).
DOC_APPEND_TIMEOUT_S = 30.0


class ArchitectRateLimitedError(GateUnavailableError):
    """Every candidate model was still rate-limited / transiently failing after the last interruptible cooldown.

    Typed gate outcome (gate_errors contract: error_class GATE_UNAVAILABLE, HTTP 503) with reason
    ARCHITECT_RATE_LIMITED. The architect stage fails (workflow `except` -> DLQ -> FAILED notification); it never
    continues with the generic deterministic plan.
    """

    http_status = 503


class SpecFetchFailedError(GateUnavailableError):
    """A Google-Doc run (spec_doc_id, no inline spec text) whose Doc text could not be read.

    Typed gate outcome (error_class GATE_UNAVAILABLE, HTTP 502) with reason SPEC_FETCH_FAILED. The architect never
    designs from the "Specification document ID: ..." placeholder.
    """

    http_status = 502


class ArchitectOutputInvalidError(GateUnavailableError):
    """Every architect model that answered returned a plan whose `compute_archetype` is not one of the exact enum
    values (schemas.COMPUTE_ARCHETYPES).

    Typed gate outcome (error_class GATE_UNAVAILABLE, HTTP 502) with reason ARCHITECT_COMPUTE_ARCHETYPE_INVALID. An
    off-enum archetype is re-asked through the model cascade (next candidate model); it is never mapped to a default
    archetype and never replaced by the generic deterministic plan.
    """

    http_status = 502


def _attach_raw_topology(plan: Any, raw: Any) -> None:
    """Lane 10: keep the model's topology exactly as returned (the gate validates it) and, when it already parses,
    expose it on the plan so the red-team critic sees it. A malformed one stays raw: never a plan-wide fallback."""
    plan._raw_service_topology = raw
    if raw is None:
        return
    try:
        plan.service_topology = _TopologyRepairSchema.model_validate(raw)
    except Exception:  # noqa: BLE001 - diagnostics come from the gate, not from here
        plan.service_topology = None


def _compute_archetype_violation(candidate: Any) -> Optional[str]:
    """repr of the plan's `compute_archetype` when it is present, not null and not an exact enum value; else None.
    Exact membership only (no case folding, no synonym table): `None` / absent keeps the bundle_id table path."""
    if not isinstance(candidate, dict) or candidate.get("compute_archetype") is None:
        return None
    value = candidate.get("compute_archetype")
    return None if isinstance(value, str) and value in COMPUTE_ARCHETYPES else repr(value)[:120]


try:
    from pydantic import ValidationError
    if not (isinstance(ValidationError, type) and issubclass(ValidationError, BaseException)):
        class ValidationError(Exception):
            pass
except Exception:
    class ValidationError(Exception):
        pass

try:
    from .prompt import ARCHITECT_SYSTEM_PROMPT, build_architect_system_prompt
    from .schemas import (
        ArchitectDecompositionResult,
        COMPUTE_ARCHETYPES,
        compute_intent_record,
        ArchitecturePlan,
        ArchitecturePlanDAG,
        BuildPlanStep,
        BuildStepCategory,
        BuildStepStatus,
        SequencedBuildPlan,
        TaskCategory,
        TaskItem,
        TaskPriority,
    )
except ImportError:
    from prompt import ARCHITECT_SYSTEM_PROMPT, build_architect_system_prompt
    from schemas import (
        ArchitectDecompositionResult,
        COMPUTE_ARCHETYPES,
        compute_intent_record,
        ArchitecturePlan,
        ArchitecturePlanDAG,
        BuildPlanStep,
        BuildStepCategory,
        BuildStepStatus,
        SequencedBuildPlan,
        TaskCategory,
        TaskItem,
        TaskPriority,
    )

try:
    from .consensus_engine import DualArchitectConsensusEngine
except ImportError:
    try:
        from consensus_engine import DualArchitectConsensusEngine
    except ImportError:
        DualArchitectConsensusEngine = None

try:  # lane 10 (FD-51): typed service-topology gate (bounded patch repair, fail loud)
    from .topology_gate import TopologyInvalidError, gate_service_topology
except ImportError:
    from topology_gate import TopologyInvalidError, gate_service_topology  # noqa: F401

try:  # PLAN-CONTRACT-CHECK: the plan's typed target files against what the platform deletes and never writes
    from .plan_contract import (OUTCOME_REPLANNED as PLAN_CONTRACT_OUTCOME_REPLANNED, ReplanAnswerUnusableError,
                                gate_defect_error, gate_plan_contract, render_contract_brief, render_contract_note)
except ImportError:
    from plan_contract import (OUTCOME_REPLANNED as PLAN_CONTRACT_OUTCOME_REPLANNED,  # noqa: F401
                               ReplanAnswerUnusableError, gate_defect_error, gate_plan_contract, render_contract_brief,
                               render_contract_note)

try:
    from shared.service_topology import ServiceTopologyIntent as _TopologyRepairSchema
except ImportError:  # pragma: no cover
    from ..shared.service_topology import ServiceTopologyIntent as _TopologyRepairSchema  # type: ignore

try:
    from .spec_decomposer import ChunkedSpecDecomposer, SpecTooLargeError
except ImportError:
    try:
        from spec_decomposer import ChunkedSpecDecomposer, SpecTooLargeError
    except ImportError:
        ChunkedSpecDecomposer = None
        SpecTooLargeError = OperatorActionRequiredError   # never raised without the decomposer

try:  # RT14-06: the one run-context object for every decomposition path
    from .context import ArchitectContext, DECOMPOSITION_PATH_MAP_REDUCE, DECOMPOSITION_PATH_SINGLE_TURN
except ImportError:
    from context import (ArchitectContext, DECOMPOSITION_PATH_MAP_REDUCE,  # type: ignore
                         DECOMPOSITION_PATH_SINGLE_TURN)


logger = logging.getLogger("castor-architect-agent")
logging.basicConfig(level=logging.INFO)

try:  # Argon compat (owner 10-14): per-model-family request rules; identity for Gemini <= 3.x
    from shared.gemini_model_config import (Purpose, ThinkingControl, adapt_generate_config_kwargs,
                                            max_output_tokens_for, resolve_model_family, thinking_config_for)
except ImportError:  # pragma: no cover
    from ..shared.gemini_model_config import (Purpose, ThinkingControl, adapt_generate_config_kwargs,  # type: ignore
                                              max_output_tokens_for, resolve_model_family, thinking_config_for)


def _reserved_thinking_tokens(model, thinking_budget):
    """FD-4CI-b RT F6: the thinking budget only reserves output room on a model that receives it (budget family, or
    an unknown id, as thinking_config_for sends it); a thinking-level model (Argon) never gets a budget: 0."""
    fam = resolve_model_family(model)
    return thinking_budget if fam is None or fam.thinking is ThinkingControl.BUDGET else 0

try:
    from shared.settings import get_model_cascade_for_agent
    from shared.cooldown_manager import (
        is_rate_limit_error,
        is_model_deprecated_error,
        is_transient_vertex_error,
        wait_for_rate_limit_cooldown,
    )
except ImportError:
    try:
        from ..shared.settings import get_model_cascade_for_agent
        from ..shared.cooldown_manager import (
            is_rate_limit_error,
            is_model_deprecated_error,
            is_transient_vertex_error,
            wait_for_rate_limit_cooldown,
        )
    except ImportError:
        def get_model_cascade_for_agent(agent_name, project_id=None):
            return [os.getenv("GEMINI_MODEL") or "gemini-4-carbon", "gemini-4-argon"]
        def is_rate_limit_error(e):
            return "429" in str(e) or "resource_exhausted" in str(e).lower()
        def is_model_deprecated_error(e):
            return "404" in str(e) or "not found" in str(e).lower()
        def is_transient_vertex_error(e):
            if e is None:
                return False
            err_str = str(e).lower()
            return any(k in err_str for k in ["429", "500", "502", "503", "504", "harpoon", "resource_exhausted", "internal error", "unavailable"])
        def wait_for_rate_limit_cooldown(*args, **kwargs):
            import time
            time.sleep(60)
            return True


class ArchitectAgent:
    # DEFAULT-MODEL-GEMINI-4-CARBON (owner 11-11): the model this agent leads with. An explicit model (constructor
    # argument or assignment) wins; otherwise the settings model of the architect role (models.architect_model, read
    # through the cached platform settings at each use, so a Settings change applies without a restart). The
    # GEMINI_MODEL env no longer outranks the settings: it used to be put first in every cascade it was not part of.
    @property
    def model_name(self) -> str:
        explicit = getattr(self, "_explicit_model_name", None)
        if explicit:
            return explicit
        cascade = get_model_cascade_for_agent("architect", project_id=getattr(self, "project_id", None) or None)
        return cascade[0]

    @model_name.setter
    def model_name(self, value: Optional[str]) -> None:
        self._explicit_model_name = value or None

    def __init__(
        self,
        project_id: Optional[str] = None,
        location: Optional[str] = None,
        model_name: Optional[str] = None,
    ):
        self.project_id = project_id or os.getenv("PROJECT_ID", "")
        self.location = location or os.getenv("GEMINI_LOCATION") or os.getenv("VERTEX_LOCATION", "global")
        self.model_name = model_name   # None: the settings architect model (the model_name property)
        self.genai_client = None
        self.model = None

        # 1. Initialize modern google-genai Client
        try:
            from google import genai
            gemini_api_key = os.getenv("GEMINI_API_KEY")
            if gemini_api_key:
                self.genai_client = genai.Client(api_key=gemini_api_key)
                logger.info(f"Initialized google-genai with API key for Architect Agent (model: '{getattr(self, '_explicit_model_name', None) or 'settings architect_model'}')")
            elif self.project_id:
                self.genai_client = genai.Client(vertexai=True, project=self.project_id, location=self.location)
                logger.info(f"Initialized google-genai Vertex AI for Architect Agent (model: '{getattr(self, '_explicit_model_name', None) or 'settings architect_model'}')")
        except Exception as e:
            logger.debug(f"google-genai init skipped ({e}); trying legacy vertexai.")

        # 2. Fallback to legacy Vertex AI GenerativeModel
        if not self.genai_client:
            try:
                import vertexai
                from vertexai.generative_models import GenerationConfig, GenerativeModel

                vertexai.init(project=self.project_id, location=self.location)
                self.model = GenerativeModel(
                    model_name=self.model_name,
                    system_instruction=[ARCHITECT_SYSTEM_PROMPT],
                    generation_config=GenerationConfig(
                        response_mime_type="application/json",
                        temperature=0.2,
                    ),
                )
                logger.info(f"Initialized legacy Vertex AI model '{self.model_name}' for Architect Agent.")
            except Exception as e:
                logger.warning(f"Vertex AI initialization skipped ({e}). Running in fallback mode.")
                self.model = None

        # 3. Initialize Dual-Architect Consensus Engine
        self.consensus_engine = None
        if DualArchitectConsensusEngine is not None:
            critic_model = os.getenv("ARCHITECT_CRITIC_MODEL", self.model_name)
            try:
                self.consensus_engine = DualArchitectConsensusEngine(
                    genai_client=self.genai_client,
                    model_name=critic_model,
                )
            except Exception as ce_err:
                logger.warning(f"Failed to initialize DualArchitectConsensusEngine: {ce_err}")
                self.consensus_engine = None

        # 4. Initialize Chunked Spec Decomposer for 90-page Map-Reduce
        self.spec_decomposer = None
        if ChunkedSpecDecomposer is not None:
            try:
                self.spec_decomposer = ChunkedSpecDecomposer(
                    genai_client=self.genai_client,
                    model_name=self.model_name,
                )
            except Exception as sd_err:
                logger.warning(f"Failed to initialize ChunkedSpecDecomposer: {sd_err}")
                self.spec_decomposer = None

    def _fetch_id_token(self, audience: str) -> str:
        """A Google ID token for `audience` from the runtime identity (the metadata server on Cloud Run): the same
        google-auth call as compliance_agent.handler.ComplianceAgentHandler._fetch_id_token."""
        from google.oauth2 import id_token as google_id_token
        from google.auth.transport.requests import Request as GoogleAuthRequest

        token = google_id_token.fetch_id_token(GoogleAuthRequest(), audience)
        if not isinstance(token, str) or not token:
            raise RuntimeError("the metadata server returned an empty ID token")
        return token

    def _workspace_auth_headers(self, url: str) -> Dict[str, str]:
        """Auth headers for a call to mcp-workspace-connector (deployed with --no-allow-unauthenticated).

        AH-1b: an ID token is minted only for an https Cloud Run origin, decided by the compliance agent's
        `id_token_audience` (exact parsed-URL checks; no other URL ever receives a token). Off Cloud Run (local dev)
        any other URL is called without a token, as before. On Cloud Run such a URL is refused, because Cloud Run IAM
        would reject a tokenless call. Raises RuntimeError when no call may be made; never logs the token.
        """
        try:
            from compliance_agent.handler import id_token_audience
        except ImportError:
            from ..compliance_agent.handler import id_token_audience

        audience = id_token_audience(url)
        if audience is None:
            if runtime_env.on_cloud_run():
                raise RuntimeError("workspace connector URL is not an https Cloud Run URL; refusing a tokenless call")
            return {}
        try:
            token = self._fetch_id_token(audience)
        except Exception as e:
            raise RuntimeError(f"could not mint an ID token for audience {audience} ({type(e).__name__})") from None
        return {"Authorization": f"Bearer {token}"}

    def _read_doc_text(self, spec_doc_id: str, workspace_mcp_url: str) -> Optional[str]:
        """The Doc's full text from mcp-workspace-connector `/read-doc`, or None (WARNING logged) on any failure,
        including an empty, blank or malformed body."""
        url = f"{workspace_mcp_url.rstrip('/')}/read-doc"
        try:
            if httpx is None:
                raise RuntimeError("httpx is not installed")
            headers = self._workspace_auth_headers(url)
            # 30 s timeout; redirects are never followed (the token is bound to this origin only).
            with httpx.Client(timeout=30.0, follow_redirects=False) as client:
                res = client.post(url, json={"document_id": spec_doc_id}, headers=headers)
                res.raise_for_status()
                data = res.json()
        except Exception as e:
            logger.warning(f"Failed to fetch document content from {url} ({type(e).__name__}: {e}).")
            return None
        full_text = data.get("full_text", "") if isinstance(data, dict) else ""
        if not isinstance(full_text, str) or not full_text.strip():
            logger.warning(f"Document {spec_doc_id} returned no text from {url}.")
            return None
        return full_text

    def fetch_spec_text_from_doc(self, spec_doc_id: str, workspace_mcp_url: str) -> str:
        """Fetches raw specification content from mcp-workspace-connector.

        Kept for callers that want text unconditionally: returns the "Specification document ID: ..." placeholder on
        failure. `decompose` does NOT use it (AH-5): a failed fetch there ends the stage with SpecFetchFailedError.
        """
        text = self._read_doc_text(spec_doc_id, workspace_mcp_url)
        if text is None:
            logger.warning(f"Using the document-ID placeholder for {spec_doc_id}.")
            return f"Specification document ID: {spec_doc_id}"
        return text

    def append_task_checklist_to_doc(
        self, spec_doc_id: str, markdown_checklist: str, workspace_mcp_url: str
    ) -> bool:
        """Appends the formatted task DAG checklist to the living Google Doc."""
        url = f"{workspace_mcp_url.rstrip('/')}/append-status"
        try:
            if httpx is None:
                raise RuntimeError("httpx is not installed")
            headers = self._workspace_auth_headers(url)
            with httpx.Client(timeout=DOC_APPEND_TIMEOUT_S, follow_redirects=False) as client:
                res = client.post(
                    url,
                    json={
                        "document_id": spec_doc_id,
                        "status_text": markdown_checklist,
                    },
                    headers=headers,
                )
                res.raise_for_status()
                logger.info(f"Successfully appended Task DAG checklist to Google Doc {spec_doc_id}")
                return True
        except Exception as e:
            logger.warning(f"Failed to append task checklist to Google Doc: {e}")
            return False

    def generate_markdown_summary(self, plan: ArchitecturePlan) -> str:
        """Constructs a clean Markdown checklist summary of the architecture plan."""
        lines = [
            "## 📋 StackVend Multi-Agent Execution Plan",
            f"**Product ID**: `{plan.product_id}` | **Policy Tier**: Tier {plan.project_tier} ({'⚠️ Human Approval Required' if plan.requires_human_approval else '✅ 100% Autonomous'})",
            f"**Complexity**: {plan.estimated_complexity}",
            "",
            "### 🏛️ Architecture Overview",
            plan.architecture_overview,
            "",
            "### 🏗️ Infrastructure Tasks (DevOps Agent)",
        ]

        if plan.infra_tasks:
            for task in plan.infra_tasks:
                task_id = getattr(task, "task_id", None) or (task.get("task_id") if isinstance(task, dict) else "")
                title = getattr(task, "title", None) or (task.get("title") if isinstance(task, dict) else "")
                depends_on = getattr(task, "depends_on", None) or (task.get("depends_on") if isinstance(task, dict) else [])
                description = getattr(task, "description", None) or (task.get("description") if isinstance(task, dict) else "")
                target_files = getattr(task, "target_files", None) or (task.get("target_files") if isinstance(task, dict) else [])
                deps = f" *(depends on: {', '.join(depends_on)})*" if depends_on else ""
                lines.append(f"- [ ] **{task_id}**: {title}{deps}")
                lines.append(f"  *Description*: {description}")
                lines.append(f"  *Target Files*: `{', '.join(target_files)}`")
        else:
            lines.append("- *(No new cloud infrastructure required)*")

        lines.append("")
        lines.append("### 💻 Application Code Tasks (Developer Agent)")
        if plan.code_tasks:
            for task in plan.code_tasks:
                task_id = getattr(task, "task_id", None) or (task.get("task_id") if isinstance(task, dict) else "")
                title = getattr(task, "title", None) or (task.get("title") if isinstance(task, dict) else "")
                depends_on = getattr(task, "depends_on", None) or (task.get("depends_on") if isinstance(task, dict) else [])
                description = getattr(task, "description", None) or (task.get("description") if isinstance(task, dict) else "")
                target_files = getattr(task, "target_files", None) or (task.get("target_files") if isinstance(task, dict) else [])
                deps = f" *(depends on: {', '.join(depends_on)})*" if depends_on else ""
                lines.append(f"- [ ] **{task_id}**: {title}{deps}")
                lines.append(f"  *Description*: {description}")
                lines.append(f"  *Target Files*: `{', '.join(target_files)}`")
        else:
            lines.append("- *(No application code changes required)*")

        lines.append("")
        lines.append(f"**Risk Assessment**: {plan.risk_assessment}")
        return "\n".join(lines)

    def uses_map_reduce(self, spec_text: str) -> bool:
        """True when this specification goes through the chunked map-reduce path (one rule, used by `decompose`; the
        consensus engine reads the path that actually produced the plan, `last_decomposition_path`: RT14 RT F3)."""
        dec = getattr(self, "spec_decomposer", None)
        return bool(dec is not None and dec.should_activate_map_reduce(spec_text))

    def decompose(
        self,
        spec_text: Optional[str] = None,
        spec_doc_id: Optional[str] = None,
        product_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        source_channel: str = "google_docs",
        workspace_mcp_url: Optional[str] = None,
        policy_matrix: Optional[Dict[str, Any]] = None,
        human_feedback: Optional[str] = None,
        bypass_consensus: bool = False,
        quota_snapshot: Optional[Dict[str, Any]] = None,
        topology_gate: bool = True,
        remediation_brief: Optional[str] = None,
        vcs_kind: Optional[str] = None,
    ) -> ArchitectDecompositionResult:
        """Main decomposition entrypoint: turns raw spec into structured Task DAG.

        `topology_gate=False` only for the consensus remediation turn's inner call: the outer call gates and
        persists the final plan's service topology (lane 10), so an intermediate plan is never recorded.
        `remediation_brief` only for that inner call too (RT14-16): the critic's faults and the draft plan, rendered
        after the operator's own REWORK guidance (`human_feedback`), never in its place.
        `vcs_kind` (PLAN-CONTRACT-CHECK): the workload's VCS kind (`GITHUB` / `SERVERLESS_GIT`), or None when unknown;
        read by the outer call's plan-contract gate only (None: the root `cloudbuild.yaml` clause is not evaluated
        and the stage trace records it)."""
        trace = trace_id or str(uuid.uuid4())
        prod = product_id or "default-workload"

        # 1. Retrieve specification text if not provided directly.
        # AH-5: a Google-Doc run (spec_doc_id, no inline text) never designs from a fake spec: if the Doc cannot be
        # read (no connector URL, auth/transport/HTTP failure, empty or malformed body) the stage fails typed.
        if (not spec_text or len(spec_text.strip()) == 0) and spec_doc_id:
            fetched = self._read_doc_text(spec_doc_id, workspace_mcp_url) if workspace_mcp_url else None
            if fetched is None:
                raise SpecFetchFailedError(
                    f"could not read the specification Doc {spec_doc_id} "
                    f"({'no workspace connector URL' if not workspace_mcp_url else 'fetch failed or empty'}); "
                    f"the architect does not design from a placeholder",
                    reason="SPEC_FETCH_FAILED",
                    details={"trace_id": trace, "product_id": prod, "spec_doc_id": spec_doc_id},
                )
            spec_text = fetched

        final_spec_text = spec_text or f"Build specification for product '{prod}'"

        # FD-4BP: set by _single_turn_decompose for the stage trace (5b); None on the Map-Reduce path.
        self.last_architect_raw_output = None
        self.last_architect_rendered_prompt = None
        self.last_test_layout_changes: List[Dict[str, Any]] = []   # TEST-LAYOUT-PLATFORM-FACT RT F3 (stage trace)
        # RT14 architect-context RT F3: the path that actually PRODUCED this plan ("map_reduce" | "single_turn"), read
        # by the consensus engine to decide whether a remediation turn can patch the draft. Re-deriving it from the
        # spec text was wrong after a map-reduce failure fell back to single-turn.
        self.last_decomposition_path: Optional[str] = None

        # RT14-06: ONE context object for every decomposition path (single-turn, map-reduce, the topology repair, the
        # critic and its remediation turn); built once here, never re-assembled from loose arguments downstream.
        current_topology = self._load_current_topology(prod)
        ctx = ArchitectContext(policy_matrix=policy_matrix, human_feedback=human_feedback,
                               quota_snapshot=quota_snapshot, current_topology=current_topology,
                               remediation_brief=remediation_brief)

        plan = None
        # Check if 90-page Map-Reduce decomposition should be activated
        # A remediation turn (remediation_brief set) patches the single-turn draft; it never re-plans via map-reduce.
        if not remediation_brief and self.uses_map_reduce(final_spec_text):
            logger.info(f"Specification for '{prod}' ({len(final_spec_text):,} chars) triggers Chunked Map-Reduce decomposition.")
            try:
                plan_dag = self.spec_decomposer.decompose_large_specification(final_spec_text, prod, context=ctx)
                plan = ArchitecturePlan(**plan_dag.model_dump())
                self.last_decomposition_path = DECOMPOSITION_PATH_MAP_REDUCE
            except (*stage_deadline.STOP_ERRORS, SpecTooLargeError):
                raise  # RT14-24: a stopped stage never falls through; RT14-06: an over-cap spec fails typed
            except Exception as mr_err:
                logger.warning(f"Map-Reduce decomposition encountered notice ({mr_err}); continuing with standard pipeline.")
                plan = None

        if not plan:
            plan = self._single_turn_decompose(
                final_spec_text=final_spec_text,
                prod=prod,
                trace=trace,
                context=ctx,
            )
            self.last_decomposition_path = DECOMPOSITION_PATH_SINGLE_TURN

        # 3. Check IPAM allocation if VPC networking required
        assigned_cidr = getattr(plan, "assigned_cidr_block", None)
        requires_vpc = getattr(plan, "requires_vpc", False) or any(
            k in final_spec_text.lower() for k in ["vpc", "vpc connector", "serverless connector", "cloud sql", "redis memory"]
        )
        if requires_vpc and not assigned_cidr:
            # Row IPAM-1 (RT F3): the VPC decision does not depend on IPAM health; an allocation failure must not
            # leave a plan with a VPC step but requires_vpc false.
            plan.requires_vpc = True
            try:
                try:
                    from shared.ipam import CastorIPAMEngine
                except ImportError:
                    from .shared.ipam import CastorIPAMEngine
                try:
                    from developer_agent.platform_facts import load_ipam_pool
                except ImportError:  # pragma: no cover - package-relative layout
                    from ..developer_agent.platform_facts import load_ipam_pool  # type: ignore
                # FD-4BZ RT F2: the same settings-driven pool as the developer stage (`orchestration.ipam_*`). With
                # the default settings this is the engine default supernet and /28, as before. An unusable settings
                # object raises here and is handled below like any IPAM failure (no range, no fallback).
                ipam_pool = load_ipam_pool(self.project_id)
                ipam_engine = CastorIPAMEngine(supernet_cidr=ipam_pool.supernet)
                try:
                    from google.cloud import firestore
                    if self.project_id:
                        ipam_engine.db = firestore.Client(project=self.project_id)
                except Exception:
                    pass
                # FD-7M-a (SAT-23 RT Q7): the ledger record carries the workload's region (the developer's resolver:
                # the recorded region, else the platform region), never the Gemini location. A region that cannot be
                # established raises here and is handled below like any IPAM failure (no range, no fallback).
                try:
                    from developer_agent.terraform_engine import resolve_workload_region
                except ImportError:  # pragma: no cover - package-relative layout
                    from ..developer_agent.terraform_engine import resolve_workload_region  # type: ignore
                ipam_region = resolve_workload_region(getattr(self, "db", None) or getattr(ipam_engine, "db", None),
                                                      product_id=prod, stage="architect")
                alloc = ipam_engine.allocate_next_cidr(
                    product_id=prod,
                    purpose=getattr(plan, "network_purpose", None) or "SERVERLESS_VPC_CONNECTOR",
                    # The architect has always sized every purpose as a connector block; kept (the connector prefix
                    # setting, default 28) so default settings give identical ranges. Per-purpose sizing
                    # (`ipam_pool.prefix_for`) would turn a WORKLOAD_SUBNET into a /24: a separate behavior change.
                    prefix_len=ipam_pool.connector_prefix,
                    region=ipam_region,
                )
                plan.requires_vpc = True
                plan.assigned_cidr_block = alloc.cidr_block
                assigned_cidr = alloc.cidr_block
                logger.info(f"IPAM allocated {alloc.cidr_block} for workload '{prod}'")
            except Exception as ipam_err:
                # Row IPAM-1: no fallback range (invariant 3). The plan carries no CIDR; the developer stage resolves
                # the range from the IPAM ledger itself (lane 11 facts) and stops with GATE_UNAVAILABLE if it cannot.
                logger.error(f"IPAM allocation failed for '{prod}'; no range assigned (no fallback): {ipam_err}")
                assigned_cidr = None
                plan.assigned_cidr_block = None

        # 4. Ensure Sequenced DAG Build Plan is populated and topologically valid
        from datetime import datetime, timezone
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()
        build_plan = getattr(plan, "sequenced_build_plan", None)
        # TI-3i: the build plan's API list is a typed plan field only when the model wrote it (never the keyword
        # fallback below, never the deterministic fallback plan)
        model_build_plan = bool(build_plan and getattr(build_plan, "steps", None)
                                and not getattr(plan, "_is_fallback", False))
        # PLAN-CONTRACT-CHECK §3.3 swap step 3: read by the outer call right after a plan-contract re-plan returns, so
        # a keyword-filled re-plan never records keyword APIs as model-typed `plan_apis`.
        self.last_build_plan_from_model = model_build_plan
        if not build_plan or not getattr(build_plan, "steps", None):
            build_plan = self._generate_sequenced_build_plan(prod, trace, final_spec_text, assigned_cidr=assigned_cidr)
            plan.sequenced_build_plan = build_plan
        else:
            build_plan.trace_id = trace
            build_plan.product_id = prod
            build_plan.plan_id = build_plan.plan_id or f"plan-{trace[:8]}"
            build_plan.created_at = build_plan.created_at or now_iso
            build_plan.total_steps = len(build_plan.steps)

        # 4b. Dual-Architect Consensus & Red-Team DAG Auditing Engine
        consensus_telemetry = None
        enable_consensus = (
            os.getenv("ENABLE_DUAL_ARCHITECT_CONSENSUS", "true").lower() == "true"
            and not bypass_consensus
        )
        if enable_consensus and getattr(self, "consensus_engine", None):
            try:
                plan, consensus_telemetry = self.consensus_engine.evaluate_and_reconcile(
                    plan=plan,
                    spec_text=final_spec_text,
                    architect_agent=self,
                    product_id=prod,
                    trace_id=trace,
                    policy_matrix=policy_matrix,
                    context=ctx,
                )
                build_plan = getattr(plan, "sequenced_build_plan", build_plan)
            except stage_deadline.STOP_ERRORS:
                raise  # RT14-24: a stopped stage is never "proceeding with draft" (which answered SUCCESS)
            except Exception as cons_err:
                logger.critical(f"Dual-Architect Consensus unexpected failure: {cons_err}. Proceeding with draft.")
        elif not enable_consensus and not bypass_consensus:
            try:
                from shared.critic_schemas import DualArchitectConsensusTelemetry
                consensus_telemetry = DualArchitectConsensusTelemetry(
                    consensus_status="BYPASSED",
                    soundness_score=1.0,
                    has_critical_findings=False,
                    remediation_performed=False,
                    remediation_diff_summary="Consensus bypassed via ENABLE_DUAL_ARCHITECT_CONSENSUS=false",
                )
            except Exception:
                pass

        # 4b'. Lane 10 (FD-51): typed service-topology gate on the FINAL plan (after consensus). One patch-style
        #      repair call (a second only when the first fixed every finding it was told, AC-4); still invalid -> TopologyInvalidError (ARCHITECT_DEFECT, 422). Never healed, never
        #      turned into critic findings (that would re-enter the remediation turn), never defaulted.
        topology_result = None
        if topology_gate and getattr(plan, "_no_model_response", False):
            # RT F7: the cascade produced no answer at all (non-429 outage): unavailable, not "output invalid".
            outage = GateUnavailableError(
                f"no architect model returned an answer for '{prod}'; the deterministic fallback plan is never used",
                reason="ARCHITECT_NO_MODEL_RESPONSE", details={"trace_id": trace, "product_id": prod})
            self._write_architect_stage_trace(trace, plan, consensus_telemetry, now_iso, topology_error=outage.to_body())
            raise outage

        # 4b''. PLAN-CONTRACT-CHECK: the final plan's typed target files against what the platform deletes and never
        #       writes, before the topology gate, so the accepted plan (draft, re-plan or stripped draft) goes through
        #       the topology gate, the test layout, the markdown, persistence and the compute record exactly once.
        #       Outer call only; the deterministic fallback plan is refused by the topology gate right after.
        plan_contract_record: Optional[Dict[str, Any]] = None
        if topology_gate and not getattr(plan, "_is_fallback", False):
            plan, build_plan, model_build_plan, consensus_telemetry, plan_contract_record = self._gate_plan_contract(
                plan, build_plan, model_build_plan, consensus_telemetry, vcs_kind=vcs_kind, trace=trace, prod=prod,
                ctx=ctx, spec_text=final_spec_text, now_iso=now_iso)

        if topology_gate:
            try:
                topology_result = gate_service_topology(
                    plan, product_id=prod, trace_id=trace,
                    repair_fn=self._topology_repair_fn(trace) if self.genai_client else None,
                    is_fallback=bool(getattr(plan, "_is_fallback", False)),
                    current_topology=ctx.current_topology)   # RT14-06 / lane-10 RT F9: brownfield context
            except TopologyInvalidError as topo_err:
                # the stage trace still records what the model returned (Glass Pane / evals), then the stage fails
                self._write_architect_stage_trace(trace, plan, consensus_telemetry, now_iso,
                                                  topology_error=topo_err.to_body(), plan_contract=plan_contract_record)
                raise
        if topology_result is not None:
            # TEST-LAYOUT-PLATFORM-FACT (owner 11-13): the gated topology's typed service list decides the plan's test
            # targets (developer_agent.workload_test_layout, row L3-PRB-t); single-service plans are unchanged.
            self.last_test_layout_changes = self._apply_test_layout(plan, build_plan, topology_result.topology.names,
                                                                    trace)

        # 4c. Generate Standard Implementation Plan Markdown for docs/planning/
        if not plan.plan_markdown or not plan.plan_file_path:
            plan_file_path, plan_markdown = self.generate_implementation_plan_markdown(
                plan=plan,
                trace_id=trace,
                product_id=prod,
                spec_text=final_spec_text,
                build_plan=build_plan,
            )
            plan.plan_file_path = plan_file_path
            plan.plan_markdown = plan_markdown
        layout_note = self._test_layout_note(self.last_test_layout_changes)
        if layout_note:   # red-team F3: the plan says the platform changed its test targets
            plan.plan_markdown = f"{(plan.plan_markdown or '').rstrip()}\n\n{layout_note}"
        contract_note = render_contract_note(plan_contract_record) if plan_contract_record else ""
        if contract_note:   # PLAN-CONTRACT-CHECK §4: the plan says the platform changed it ("" for a passed plan)
            plan.plan_markdown = f"{(plan.plan_markdown or '').rstrip()}\n\n{contract_note}"

        # 5. Persist Build Plan & Implementation Plan to Firestore. RT14-24: nothing is persisted for a stage that was
        #    abandoned (cancel, supersede, emergency stop) or has already answered; reserve 0 = only past the deadline.
        stage_deadline.guard_side_effect("architect.persist", reserve_s=0)
        self.persist_build_plan_to_firestore(build_plan)
        self.persist_implementation_plan_to_firestore(prod, plan.plan_file_path, plan.plan_markdown, trace)

        # 5b. HD-01/HD-02 replacement: the plan's typed compute fields (service set, bundle) for the developer, which
        #     reads them by trace id (the workflow passes only the task DAG); returned on the result as well. A failed
        #     write is logged as an error: the developer then uses the repository's pinned compute or the recorded
        #     platform default (never the spec text).
        compute_intent = compute_intent_record(
            plan, topology_result.topology if topology_result else None,
            topology_result.provenance() if topology_result else None,
            plan_apis=(list(getattr(build_plan, "required_cloud_apis", None) or [])   # TI-3i
                       if model_build_plan and build_plan is not None else None))
        # Lane 10 (RT F4): the gated record (with its service topology) is persisted INSIDE the gate: a failed write
        # fails the architect stage (GATE_UNAVAILABLE). The developer reads it by this trace id only, so it can
        # never fall back to an earlier run's topology. (No project id = harness / unit tests: returned only.)
        if topology_gate and self.project_id and trace:
            payload: Dict[str, Any] = {"architect_compute_intent": compute_intent}
            # RT14-30: field-path merge, so each listed field is REPLACED, never deep-merged: a REWORK from a push
            # topology to a pull topology must not keep the earlier `pushes` (or `required_cloud_apis`) beside the
            # new sha256 (TOPOLOGY.RECORD_SHA_MISMATCH). The rest of the run document is left as it is.
            # RT F4: this run's repair events are ALWAYS written ([] without a repair turn), so a REWORK without a
            # repair never keeps the previous attempt's events.
            repair_events: List[Dict[str, Any]] = []
            if topology_result is not None and topology_result.repair_event is not None:
                repair_events = [   # AC-4: one per repair turn (<= 2)
                    ev.model_dump(mode="json") for ev in (topology_result.repair_events
                                                          or [topology_result.repair_event])]
            payload["stages"] = {"architect": {"repair_events": repair_events}}
            fields = ["architect_compute_intent", "stages.architect.repair_events"]
            try:
                self._firestore_client().collection("pipeline_executions").document(trace).set(payload, merge=fields)
            except Exception as ci_err:  # noqa: BLE001 - typed below; never silent
                raise GateUnavailableError(
                    f"the architect's compute intent / service topology for trace '{trace}' could not be persisted: "
                    f"{type(ci_err).__name__}: {ci_err}", reason="ARCHITECT_TOPOLOGY_PERSIST_FAILED",
                    details={"trace_id": trace, "product_id": prod}) from ci_err
        # Persist Stage Execution Trace for Glass Pane & Evals
        self._write_architect_stage_trace(trace, plan, consensus_telemetry, now_iso, plan_contract=plan_contract_record)

        # 6. Combine tasks into unified DAG
        task_dag: List[TaskItem] = []
        task_dag.extend(plan.infra_tasks)
        task_dag.extend(plan.code_tasks)

        # 7. Generate Markdown checklist summary
        markdown_summary = self.generate_markdown_summary(plan)

        # 8. Optionally update the living Google Doc. RT14-24: never for an abandoned or answered stage (the guard
        #    raises the stop); a best-effort append that could outlast the stage's answer is skipped, logged.
        if spec_doc_id and workspace_mcp_url:
            stage_deadline.guard_side_effect("architect.doc_append", reserve_s=0)
            left = stage_deadline.remaining_s()
            if left is not None and left < DOC_APPEND_TIMEOUT_S:
                logger.warning(f"Task checklist not appended to Google Doc {spec_doc_id}: {int(left)} s of the "
                               f"architect stage budget left, the append may take {int(DOC_APPEND_TIMEOUT_S)} s")
            else:
                self.append_task_checklist_to_doc(spec_doc_id, markdown_summary, workspace_mcp_url)

        return ArchitectDecompositionResult(
            trace_id=trace,
            product_id=plan.product_id or prod,
            spec_doc_id=spec_doc_id or "",
            architecture_plan=plan,
            task_dag=task_dag,
            sequenced_build_plan=build_plan,
            infra_plan={
                "infra_tasks_count": len(plan.infra_tasks),
                "tasks": [t.model_dump() if hasattr(t, "model_dump") else t for t in plan.infra_tasks],
                "requires_approval": plan.requires_human_approval,
            },
            markdown_summary=markdown_summary,
            plan_markdown=plan.plan_markdown,
            plan_file_path=plan.plan_file_path,
            consensus_telemetry=consensus_telemetry,
            compute_intent=compute_intent,
        )

    @staticmethod
    def _apply_test_layout(plan: Any, build_plan: Any, service_names: Any, trace: str) -> List[Dict[str, Any]]:
        """TEST-LAYOUT-PLATFORM-FACT: in a multi-service plan no task or build step targets the repository-root
        `tests/` directory, the place the platform's layout rule forbids (workload_test_layout.plan_test_target_changes:
        relocated to `apps/<svc>/tests/` when the task names exactly one service by an exact `apps/<svc>/` path,
        else removed). Returns one record per changed task or step (red-team F3: written to the architect stage trace
        and stated in the plan markdown), and logs each. One service: nothing changes, [] returned."""
        try:
            from developer_agent.workload_test_layout import is_multi_service, plan_test_target_changes
        except ImportError:  # pragma: no cover - package-relative layout
            from ..developer_agent.workload_test_layout import is_multi_service, plan_test_target_changes  # type: ignore
        if not is_multi_service(service_names):
            return []
        items = [("task", t, getattr(t, "task_id", None))
                 for t in list(getattr(plan, "infra_tasks", None) or []) + list(getattr(plan, "code_tasks", None) or [])]
        items += [("build_step", s, getattr(s, "step_id", None)) for s in (getattr(build_plan, "steps", None) or [])]
        changes: List[Dict[str, Any]] = []
        for kind, item, item_id in items:
            targets = getattr(item, "target_files", None)
            if not isinstance(targets, list):
                continue
            new, relocated, removed = plan_test_target_changes(targets, service_names)
            if relocated or removed:
                item.target_files = new
                changes.append({"kind": kind, "id": str(item_id), "relocated": [list(p) for p in relocated],
                                "removed": list(removed)})
                logger.info(f"Test layout for trace '{trace}': {kind} {item_id!r}: {len(relocated)} root tests/ "
                            f"target(s) relocated to apps/<service>/tests/, {len(removed)} removed "
                            f"(multi-service layout rule)")
        return changes

    @staticmethod
    def _test_layout_note(changes: List[Dict[str, Any]]) -> str:
        """Red-team F3: the plan markdown's statement of the platform's test-layout changes ("" when none)."""
        if not changes:
            return ""
        lines = ["## Platform test layout", "",
                 "This workload has more than one service, so the platform keeps each service's tests in "
                 "`apps/<service>/tests/` and never in the repository-root `tests/` directory. These plan targets "
                 "were changed when the plan was made:"]
        for c in changes:
            label = "Task" if c["kind"] == "task" else "Build step"
            parts = [f"`{old}` -> `{new}`" for old, new in c["relocated"]]
            if c["removed"]:
                parts.append("removed " + ", ".join(f"`{p}`" for p in c["removed"])
                             + " (no single service named; each service's tests go in its own `apps/<service>/tests/`)")
            lines.append(f"- {label} `{c['id']}`: " + "; ".join(parts))
        return "\n".join(lines) + "\n"

    def _gate_plan_contract(self, plan: Any, build_plan: Any, model_build_plan: bool, consensus_telemetry: Any, *,
                            vcs_kind: Optional[str], trace: str, prod: str, ctx: "ArchitectContext", spec_text: str,
                            now_iso: str) -> Tuple[Any, Any, bool, Any, Dict[str, Any]]:
        """PLAN-CONTRACT-CHECK (plan §3.1, §3.3, §4): run `plan_contract.gate_plan_contract` on the final plan and
        return `(plan, build_plan, model_build_plan, consensus_telemetry, record)` for the rest of `decompose`.

        - No violation: the SAME objects come back unchanged (Do No Harm) with the PASSED record.
        - Accepted re-plan: every local derived from the plan is rebound to the re-plan (swap steps 1-6).
        - Draft kept (strip): the draft, with the flagged entries removed by the gate (a CI-file entry the QA
          judge's task facts rest on is kept, `plan_contract.strip_violations`).
        Every exception that leaves the gate is typed; a `GateError` other than a stage stop gets the stage trace
        (with the `plan_contract` record attached by the gate) written first, then propagates unchanged; any other
        exception becomes PlatformDefectError PLAN_CONTRACT_GATE_DEFECT, trace first (code review finding 4)."""
        # The inner re-plan call resets these (RT14 F3 path, raw output, prompt, model build plan): kept from the draft.
        draft_state = {name: getattr(self, name, None) for name in _PLAN_CONTRACT_DRAFT_ATTRS}
        is_map_reduce = draft_state["last_decomposition_path"] == DECOMPOSITION_PATH_MAP_REDUCE

        def restore_draft_state() -> None:
            for name, value in draft_state.items():
                setattr(self, name, value)

        result = None
        try:
            result = gate_plan_contract(
                plan, vcs_kind=vcs_kind,
                replan_fn=self._plan_contract_replan_fn(trace, prod, ctx, spec_text) if self.genai_client else None,
                is_map_reduce=is_map_reduce, trace_id=trace, product_id=prod,
                read_model_build_plan=lambda: getattr(self, "last_build_plan_from_model", None))
        except stage_deadline.STOP_ERRORS:
            raise  # RT14-24: nothing is recorded for a stopped stage (the draft state is restored in `finally`)
        except GateError as gate_err:
            # FAIL exhaustion (PlanContractViolationError), under FAIL a re-plan outage (no model answer:
            # ARCHITECT_NO_MODEL_RESPONSE; rate limit), any other typed error of the inner call, or a gate defect
            # (PLAN_CONTRACT_GATE_DEFECT): the trace shows the draft and the record. Under STRIP an outage of the
            # re-plan is a failed turn (REPLAN_MODEL_UNAVAILABLE) and the stripped draft comes back as a result.
            restore_draft_state()
            record = getattr(gate_err, "plan_contract_record", None)
            outage = (isinstance(gate_err, GateUnavailableError)
                      and getattr(gate_err, "reason", None) == "ARCHITECT_NO_MODEL_RESPONSE")
            self._write_architect_stage_trace(trace, plan, consensus_telemetry, now_iso,
                                              topology_error=gate_err.to_body() if outage else None,
                                              plan_contract=record)
            raise
        except Exception as e:  # noqa: BLE001 - code review finding 4: never an untyped stage (invariant 8)
            # the gate types its own defects; this covers the call around it. Trace first, then the typed error.
            restore_draft_state()
            defect = gate_defect_error(e, trace_id=trace, product_id=prod, record={
                "outcome": None, "vcs_kind": vcs_kind, "turns": [], "stripped": []})
            self._write_architect_stage_trace(trace, plan, consensus_telemetry, now_iso,
                                              plan_contract=defect.plan_contract_record)
            raise defect from e
        finally:
            if result is None:   # any exception (incl. a stage stop): the draft stays the stage's output
                restore_draft_state()

        accepted = getattr(result.plan, "architecture_plan", result.plan)
        if result.outcome != PLAN_CONTRACT_OUTCOME_REPLANNED:
            restore_draft_state()   # passed or stripped: the draft stays the stage's output
            if accepted is not plan:   # §8.1 strips the draft in place; a stripped copy is taken the same way
                plan, build_plan = accepted, getattr(accepted, "sequenced_build_plan", None)
            return plan, build_plan, model_build_plan, consensus_telemetry, result.record

        # §3.3 swap: the accepted re-plan replaces the draft in every derived local.
        plan = accepted                                                          # 1
        build_plan = getattr(plan, "sequenced_build_plan", None)                 # 2 (the inner call filled a missing one)
        model_build_plan = bool(result.replanned_model_build_plan)               # 3
        if consensus_telemetry is not None and hasattr(consensus_telemetry, "model_copy"):   # 4
            prior = getattr(consensus_telemetry, "remediation_diff_summary", None)
            consensus_telemetry = consensus_telemetry.model_copy(update={
                "remediation_diff_summary": f"{prior} {PLAN_CONTRACT_TELEMETRY_NOTE}" if prior
                else PLAN_CONTRACT_TELEMETRY_NOTE})
        # 5: the inner call rendered plan_markdown / plan_file_path from the re-plan; the note is appended in 4c.
        # 6: self.last_architect_raw_output already holds the accepted re-plan's raw answer (inner call).
        logger.info(f"Plan contract for trace '{trace}': draft refused, re-plan accepted "
                    f"({len(getattr(plan, 'infra_tasks', None) or [])} infra / "
                    f"{len(getattr(plan, 'code_tasks', None) or [])} code tasks)")
        return plan, build_plan, model_build_plan, consensus_telemetry, result.record

    def _plan_contract_replan_fn(self, trace: str, prod: str, ctx: "ArchitectContext", spec_text: str):
        """PLAN-CONTRACT-CHECK §3.3: the re-plan turn, the SAME inner call as the consensus remediation turn
        (`DualArchitectConsensusEngine._execute_remediation_turn`): the run's context unchanged, the contract brief
        after the operator's REWORK guidance, then the draft's typed JSON and compute decision; consensus bypassed,
        no topology gate (the outer call gates the accepted plan once). Returns the inner ArchitectDecompositionResult;
        every exception propagates to the gate, which types it, except ArchitectOutputInvalidError (every model
        answered with an off-enum archetype: a bad answer, not an outage), which becomes ReplanAnswerUnusableError, a
        failed turn that keeps the audited draft (code review finding 3). A model outage (ArchitectRateLimitedError,
        no model answer) is typed by the gate: a failed turn REPLAN_MODEL_UNAVAILABLE under STRIP, GATE_UNAVAILABLE
        under FAIL."""
        def replan(draft: Any, violations: List[Any]) -> ArchitectDecompositionResult:
            if DualArchitectConsensusEngine is None:
                raise RuntimeError("the draft renderers (consensus_engine) are not importable")
            brief = (render_contract_brief(violations)
                     + DualArchitectConsensusEngine._draft_plan_json(draft, subject=PLAN_CONTRACT_DRAFT_SUBJECT)
                     + DualArchitectConsensusEngine._draft_compute_decision(draft))
            try:
                return self.decompose(
                    spec_text=spec_text,
                    product_id=prod,
                    trace_id=trace,
                    policy_matrix=ctx.policy_matrix,
                    human_feedback=ctx.human_feedback,
                    quota_snapshot=ctx.quota_snapshot,
                    remediation_brief=brief,
                    bypass_consensus=True,
                    topology_gate=False,
                )
            except ArchitectOutputInvalidError as bad:
                raise ReplanAnswerUnusableError(str(bad), reason=bad.reason) from bad
        return replan

    def _write_architect_stage_trace(self, trace: str, plan: Any, consensus_telemetry: Any, now_iso: str,
                                     topology_error: Optional[Dict[str, Any]] = None,
                                     plan_contract: Optional[Dict[str, Any]] = None) -> None:
        """Best-effort stage trace for the Glass Pane & evals (unchanged contract; lane 10 adds `topology_error`
        when the topology gate refused the plan; PLAN-CONTRACT-CHECK adds `plan_contract`, the gate's record, on
        every exit after the gate ran)."""
        if not (self.project_id and trace):
            return
        try:
            fs = self._firestore_client()
            # FD-4BP: raw_json / rendered_sys_prompt are locals of _single_turn_decompose, not of this method
            # (the NameError was swallowed below, so this trace was never written). Read what it recorded.
            raw_model_output = getattr(self, "last_architect_raw_output", None)
            trace_payload = {
                "trace_id": trace,
                "stage_name": "architect",
                "rendered_prompt": getattr(self, "last_architect_rendered_prompt", None) or ARCHITECT_SYSTEM_PROMPT,
                "agent_output": (raw_model_output or plan.model_dump_json()) if hasattr(plan, "model_dump_json") else str(plan),
                "created_at": now_iso,
                "is_few_shot_candidate": False,
            }
            if topology_error is not None:
                trace_payload["topology_error"] = topology_error
            if plan_contract is not None:
                trace_payload["plan_contract"] = plan_contract
            layout_changes = getattr(self, "last_test_layout_changes", None)
            if layout_changes:   # TEST-LAYOUT-PLATFORM-FACT RT F3: what the platform changed in the plan
                trace_payload["test_layout_changes"] = list(layout_changes)
            if consensus_telemetry:
                t_dict = consensus_telemetry.model_dump() if hasattr(consensus_telemetry, "model_dump") else consensus_telemetry
                trace_payload["architect_consensus"] = t_dict
            # RT14-30: every field this stage owns is replaced (field-path merge), so an optional field of an earlier
            # architect run of this trace (`topology_error`, `test_layout_changes`, `architect_consensus`) never
            # survives next to this run's output (absent here = deleted); fields other writers add (Control Center
            # ratings) are kept.
            from google.cloud.firestore_v1.transforms import DELETE_FIELD
            for owned in ARCHITECT_STAGE_TRACE_FIELDS:
                trace_payload.setdefault(owned, DELETE_FIELD)
            fs.collection("pipeline_executions").document(trace).collection("stage_traces").document("architect").set(
                trace_payload, merge=list(ARCHITECT_STAGE_TRACE_FIELDS))
            if consensus_telemetry:
                t_dict = consensus_telemetry.model_dump() if hasattr(consensus_telemetry, "model_dump") else consensus_telemetry
                fs.collection("pipeline_executions").document(trace).set({
                    "stages": {
                        "architect": {
                            "details": {
                                "architect_consensus": t_dict,
                            }
                        }
                    }
                }, merge=["stages.architect.details.architect_consensus"])
            logger.info(f"Persisted stage trace for '{trace}' stage 'architect'")
        except Exception as tr_err:
            logger.debug(f"Stage trace persistence notice for {trace}: {tr_err}")

    def _firestore_client(self) -> Any:
        """One Firestore client per agent for the lane 10 paths and the stage trace: `self.db` when injected, else
        built once (a construction failure is remembered and re-raised, never retried per write)."""
        db = getattr(self, "db", None)
        if db is not None:
            return db
        cached = getattr(self, "_fs_client_cache", None)
        if isinstance(cached, BaseException):
            raise cached
        if cached is not None:
            return cached
        try:
            from google.cloud import firestore
            self._fs_client_cache = firestore.Client(project=self.project_id)
        except Exception as e:  # noqa: BLE001 - re-raised to the caller (typed there)
            self._fs_client_cache = e
            raise
        return self._fs_client_cache

    def _load_current_topology(self, prod: str) -> Optional[Dict[str, Any]]:
        """workloads/{prod}.service_topology.record.intent (written after a committed topology run), re-validated;
        None when absent, invalid or unreadable (prompt context only, never an authority)."""
        if not self.project_id or not prod:
            return None
        try:
            from shared.service_topology import topology_from_record
            doc = self._firestore_client().collection("workloads").document(prod).get()
            data = (doc.to_dict() or {}) if getattr(doc, "exists", False) else {}
            record = ((data.get("service_topology") or {}).get("record")) if isinstance(data, dict) else None
            vt, _ = topology_from_record(record, product_id=prod, file="workloads.service_topology")
            return vt.canonical_dict() if vt is not None else None
        except Exception as e:  # noqa: BLE001 - context only
            logger.warning(f"Current service topology of '{prod}' not loaded (no context for the architect): {e}")
            return None

    def _topology_repair_fn(self, trace: str):
        """The topology gate's one patch call (RT F5): ONE `generate_content` on the first architect model, with
        `response_schema=ServiceTopologyIntent`; no cascade, no re-decomposition, no map-reduce, no consensus.
        Returns (text, model, tokens_in, tokens_out); any exception propagates to the gate (-> typed failure)."""
        def repair(system_instruction: str, prompt: str):
            from google.genai import types
            models = get_model_cascade_for_agent("architect", project_id=self.project_id)
            model = self.model_name or (models[0] if models else "gemini")
            cfg: Dict[str, Any] = {"system_instruction": system_instruction, "response_mime_type": "application/json",
                                   "response_schema": _TopologyRepairSchema, "temperature": 0.1}
            if hasattr(types, "AutomaticFunctionCallingConfig"):
                cfg["automatic_function_calling"] = types.AutomaticFunctionCallingConfig(disable=True)
            res = self.genai_client.models.generate_content(
                model=model, contents=prompt,
                config=stage_deadline.bound_llm_config(   # STAGE-DEADLINE: checkpoint + budget-bound call
                    types.GenerateContentConfig(**adapt_generate_config_kwargs(model, Purpose.ARCHITECT, cfg,
                                                                               types=types)),
                    "architect.topology_repair", types=types))
            tin = tout = 0
            try:
                from shared.token_accounting import extract_token_usage, record_agent_tokens
                usage = extract_token_usage(res, model_name=model)
                if usage:
                    tin, tout = int(usage.prompt_tokens or 0), int(usage.candidates_tokens or 0)
                    if trace and self.project_id:
                        from google.cloud import firestore
                        fs_db = getattr(self, "db", None) or firestore.Client(project=self.project_id)
                        record_agent_tokens(fs_db, trace, "architect", usage)
            except Exception as tok_err:  # noqa: BLE001 - accounting is best-effort, as for every architect call
                logger.debug(f"Architect topology-repair token accounting notice: {tok_err}")
            return (getattr(res, "text", None) or "").strip(), model, tin, tout
        return repair

    def _single_turn_decompose(
        self,
        final_spec_text: str,
        prod: str,
        trace: str,
        context: Optional[ArchitectContext] = None,
    ) -> ArchitecturePlan:
        """Standard single-turn Gemini prompt decomposition for specs under 25k chars. `context` (RT14-06): the run's
        ArchitectContext, the same object the map-reduce path renders."""
        ctx = context or ArchitectContext()
        raw_json = None
        any_model_answered = False
        rate_limit_exhausted = False
        archetype_rejections: List[Dict[str, str]] = []  # off-enum compute_archetype answers (model, value)
        max_cooldown_attempts = 3
        prompt_content = (
            f"Deconstruct the following technical specification for product '{prod}'.\n\n"
            f"--- SPECIFICATION CONTENT ---\n{final_spec_text}\n--- END SPECIFICATION ---"
        )

        # RT14-06: organization policies, operator REWORK guidance, current topology (and, for the consensus
        # remediation turn, the critic's brief): one renderer shared with the map-reduce map prompts.
        prompt_content += ctx.prompt_blocks()

        if self.genai_client:
            models_to_try = get_model_cascade_for_agent("architect", project_id=self.project_id)
            # DEFAULT-FALLBACK-CHAIN: an explicit model leads even when it is also one of the fallback models (it used
            # to be added only when absent, so a fallback id given explicitly was asked after the settings model)
            if self.model_name:
                models_to_try = [self.model_name] + [m for m in models_to_try if m != self.model_name]

            cooldown_attempt = 1

            # AH-2: one model pass after each of the 3 cooldowns (the 4th call to the cooldown helper returns False
            # at once: "max attempts reached"); still all rate-limited then -> ArchitectRateLimitedError below.
            while not raw_json and cooldown_attempt <= max_cooldown_attempts + 1:
                all_rate_limited = True
                last_rate_model = models_to_try[0] if models_to_try else "gemini"

                for m_name in list(models_to_try):
                    if not m_name:
                        continue
                    try:
                        from google.genai import types
                        try:
                            from shared.settings import get_platform_settings
                            settings = get_platform_settings(project_id=self.project_id)
                            token_limit = settings.models.get_architect_token_limit()
                            # FD-4CI-b: Settings > Thinking Budget (0 = no thinking config, as before)
                            from shared.settings import thinking_budget_of
                            thinking_budget = thinking_budget_of(settings)
                        except Exception:
                            token_limit = 65536
                            thinking_budget = 0

                        token_limit = max_output_tokens_for(
                            m_name, token_limit, Purpose.ARCHITECT,
                            reserved_thinking_tokens=_reserved_thinking_tokens(m_name, thinking_budget))
                        rendered_sys_prompt = build_architect_system_prompt(task_context=final_spec_text, quota_snapshot=ctx.quota_snapshot)
                        self.last_architect_rendered_prompt = rendered_sys_prompt  # FD-4BP: stage trace
                        gen_config_kwargs = {
                            "system_instruction": rendered_sys_prompt,
                            "response_mime_type": "application/json",
                            "response_schema": ArchitecturePlanDAG,
                            "temperature": 0.1,
                            "max_output_tokens": token_limit,
                        }
                        tc = thinking_config_for(m_name, thinking_budget, Purpose.ARCHITECT, types=types)
                        if tc is not None:
                            gen_config_kwargs["thinking_config"] = tc
                        if hasattr(types, "AutomaticFunctionCallingConfig"):
                            gen_config_kwargs["automatic_function_calling"] = types.AutomaticFunctionCallingConfig(disable=True)
                        res = self.genai_client.models.generate_content(
                            model=m_name,
                            contents=prompt_content,
                            config=stage_deadline.bound_llm_config(   # STAGE-DEADLINE: checkpoint + bound call
                                types.GenerateContentConfig(**adapt_generate_config_kwargs(
                                    m_name, Purpose.ARCHITECT, gen_config_kwargs, types=types)),
                                "architect.decompose", types=types),
                        )

                        # Token Accounting: Extract and record tokens immediately
                        try:
                            from shared.token_accounting import extract_token_usage, record_agent_tokens
                            usage_record = extract_token_usage(res, model_name=m_name)
                            if usage_record:
                                self.last_architect_tokens = usage_record
                                if trace and self.project_id:
                                    from google.cloud import firestore
                                    fs_db = getattr(self, "db", None) or firestore.Client(project=self.project_id)
                                    record_agent_tokens(fs_db, trace, "architect", usage_record)
                        except Exception as tok_err:
                            logger.debug(f"Architect token accounting notice: {tok_err}")

                        # Check for token limit truncation via finish_reason
                        if res and hasattr(res, "candidates") and res.candidates:
                            candidate = res.candidates[0]
                            finish_reason = getattr(candidate, "finish_reason", None)
                            finish_reason_str = str(finish_reason).upper()
                            if "MAX_TOKENS" in finish_reason_str:
                                logger.critical(
                                    f"TOKEN_LIMIT_EXCEEDED: Model '{m_name}' reached output token limit ({token_limit}). "
                                    f"Response was truncated mid-generation. Pruning from current run and cascading to next candidate."
                                )
                                models_to_try = [cm for cm in models_to_try if cm != m_name]
                                all_rate_limited = False
                                continue

                        if res and res.text:
                            any_model_answered = True   # RT F7: an answer (even unparseable) is not an outage
                            candidate_text = res.text.strip()
                            # In-loop validation: Ensure JSON parses before accepting candidate
                            try:
                                parsed = json.loads(candidate_text, strict=False)
                                accepted = candidate_text
                                accepted_msg = (f"Successfully generated architecture decomposition with model "
                                                f"'{m_name}' (token limit: {token_limit})")
                            except Exception as parse_err:
                                # Attempt quick regex cleanup
                                try:
                                    cleaned = re.sub(r'[\x00-\x1f\x7f-\x9f]', lambda m: ' ' if m.group(0) in '\r\n\t' else '', candidate_text)
                                    parsed = json.loads(cleaned, strict=False)
                                    accepted = cleaned
                                    accepted_msg = f"Successfully generated & cleaned architecture decomposition with model '{m_name}'"
                                except Exception:
                                    logger.warning(
                                        f"Model '{m_name}' produced corrupt or truncated JSON: {parse_err}. "
                                        f"Length: {len(candidate_text)}. Cascading to next candidate..."
                                    )
                                    models_to_try = [cm for cm in models_to_try if cm != m_name]
                                    all_rate_limited = False
                                    continue
                            # Exact-enum check of the typed compute archetype: an off-enum value is re-asked through
                            # the cascade (next candidate model), never defaulted (ArchitectOutputInvalidError below).
                            bad_archetype = _compute_archetype_violation(parsed)
                            if bad_archetype is not None:
                                archetype_rejections.append({"model": m_name, "compute_archetype": bad_archetype})
                                logger.warning(
                                    f"Model '{m_name}' returned compute_archetype={bad_archetype}, not one of "
                                    f"{list(COMPUTE_ARCHETYPES)}. Cascading to next candidate..."
                                )
                                models_to_try = [cm for cm in models_to_try if cm != m_name]
                                all_rate_limited = False
                                continue
                            raw_json = accepted
                            logger.info(accepted_msg)
                            all_rate_limited = False
                            break
                    except stage_deadline.STOP_ERRORS:
                        raise  # STAGE-DEADLINE: never cascade past a stopped stage
                    except Exception as e:
                        if is_model_deprecated_error(e):
                            logger.warning(f"Model '{m_name}' is deprecated or not found (404). Pruning from candidate cascade.")
                            models_to_try = [cm for cm in models_to_try if cm != m_name]
                            all_rate_limited = False
                            continue
                        elif is_transient_vertex_error(e):
                            logger.warning(f"Model '{m_name}' hit transient Vertex AI error (429 / 500 / Harpoon: {e}). Trying next candidate...")
                            last_rate_model = m_name
                            continue
                        else:
                            logger.warning(f"google-genai generation with model '{m_name}' failed: {e}. Trying next candidate...")
                            all_rate_limited = False

                if raw_json or not all_rate_limited:
                    break

                if all_rate_limited and not raw_json:
                    logger.warning(
                        f"All architect candidate models ({models_to_try}) hit transient Vertex AI errors. "
                        f"Entering interruptible 60s cooldown (cycle {cooldown_attempt}/{max_cooldown_attempts})."
                    )
                    should_retry = wait_for_rate_limit_cooldown(
                        trace_id=trace,  # FD24-01: this method's parameters are `trace` / `prod`
                        product_id=prod,
                        stage="architect_decomposition",
                        model_name=last_rate_model,
                        attempt=cooldown_attempt,
                        max_attempts=max_cooldown_attempts,
                        project_id=self.project_id,
                    )
                    if not should_retry:
                        rate_limit_exhausted = True
                        break
                    cooldown_attempt += 1

        if not raw_json and self.model:
            stage_deadline.checkpoint("architect.legacy_model")   # STAGE-DEADLINE: outside the try (never swallowed)
            try:
                response = self.model.generate_content(prompt_content)
                if response and response.text:
                    raw_json = response.text.strip()
            except Exception as e:
                logger.warning(f"Legacy model generation failed: {e}")

        # Off-enum compute_archetype (exact enum, schemas.COMPUTE_ARCHETYPES): the legacy path is checked here, and when
        # every model that answered was off-enum the stage fails typed - never a default archetype, never the generic
        # deterministic plan. Checked before the rate-limit outcome: a model did answer.
        if raw_json:
            legacy_parsed = None  # unparseable even after the cleanup: the parse/fallback path below handles it as before
            for text in (raw_json, re.sub(r'[\x00-\x1f\x7f-\x9f]', lambda m: ' ' if m.group(0) in '\r\n\t' else '', raw_json)):
                try:
                    legacy_parsed = json.loads(text, strict=False)
                    break
                except Exception:
                    continue
            bad_archetype = _compute_archetype_violation(legacy_parsed)
            if bad_archetype is not None:
                archetype_rejections.append({"model": "legacy", "compute_archetype": bad_archetype})
                raw_json = None
        if not raw_json and archetype_rejections:
            raise ArchitectOutputInvalidError(
                f"every architect model that answered returned a compute_archetype outside {list(COMPUTE_ARCHETYPES)}",
                reason="ARCHITECT_COMPUTE_ARCHETYPE_INVALID",
                details={"trace_id": trace, "product_id": prod, "rejections": archetype_rejections},
            )

        if not raw_json and rate_limit_exhausted:
            # AH-2 (fail closed): never continue with the generic deterministic plan because of rate limits.
            raise ArchitectRateLimitedError(
                f"every architect model was still rate-limited after {max_cooldown_attempts} cooldowns",
                reason="ARCHITECT_RATE_LIMITED",
                details={"trace_id": trace, "product_id": prod, "cooldowns": max_cooldown_attempts},
            )

        self.last_architect_raw_output = raw_json  # FD-4BP: stage trace "agent_output" (decompose step 5b)
        used_fallback = False
        no_model_response = False
        if raw_json:
            try:
                plan_dict = json.loads(raw_json, strict=False)
                if "infra_tasks" in plan_dict and isinstance(plan_dict["infra_tasks"], list):
                    plan_dict["infra_tasks"] = [
                        TaskItem(**t) if isinstance(t, dict) else t for t in plan_dict["infra_tasks"]
                    ]
                if "code_tasks" in plan_dict and isinstance(plan_dict["code_tasks"], list):
                    plan_dict["code_tasks"] = [
                        TaskItem(**t) if isinstance(t, dict) else t for t in plan_dict["code_tasks"]
                    ]
                # Lane 10: the topology is validated by the topology gate (diagnostics + one repair), not by this
                # parse, so a malformed topology never turns the whole answer into the deterministic fallback plan.
                raw_topology = plan_dict.pop("service_topology", None) if isinstance(plan_dict, dict) else None
                plan_dag = ArchitecturePlanDAG(**plan_dict)
                plan = ArchitecturePlan(**plan_dict)
                _attach_raw_topology(plan, raw_topology)
            except (json.JSONDecodeError, ValidationError) as e:
                try:
                    cleaned_json = re.sub(r'[\x00-\x1f\x7f-\x9f]', lambda m: ' ' if m.group(0) in '\r\n\t' else '', raw_json)
                    plan_dict = json.loads(cleaned_json, strict=False)
                    if "infra_tasks" in plan_dict and isinstance(plan_dict["infra_tasks"], list):
                        plan_dict["infra_tasks"] = [
                            TaskItem(**t) if isinstance(t, dict) else t for t in plan_dict["infra_tasks"]
                        ]
                    if "code_tasks" in plan_dict and isinstance(plan_dict["code_tasks"], list):
                        plan_dict["code_tasks"] = [
                            TaskItem(**t) if isinstance(t, dict) else t for t in plan_dict["code_tasks"]
                        ]
                    raw_topology = plan_dict.pop("service_topology", None) if isinstance(plan_dict, dict) else None
                    plan_dag = ArchitecturePlanDAG(**plan_dict)
                    plan = ArchitecturePlan(**plan_dict)
                    _attach_raw_topology(plan, raw_topology)
                except Exception as exc:
                    logger.critical(
                        f"ARCHITECT_FALLBACK_TRIGGERED: Model generation failed or rejected for '{prod}'. "
                        f"Trace: {trace}. Reason: {exc}. Raw response: {raw_json[:500]}"
                    )
                    plan = self._fallback_plan(prod, final_spec_text)
                    used_fallback = True
        else:
            logger.critical(
                f"ARCHITECT_FALLBACK_TRIGGERED: No model response received for '{prod}'. Trace: {trace}."
            )
            plan = self._fallback_plan(prod, final_spec_text)
            used_fallback = True
            no_model_response = not any_model_answered

        if used_fallback:
            # Lane 10: the deterministic fallback plan never passes the topology gate (it has no model topology).
            # RT F7: when no model answered at all it is an outage (GATE_UNAVAILABLE), not an architect defect.
            try:
                plan._is_fallback = True
                plan._no_model_response = no_model_response
            except Exception:  # noqa: BLE001 - test doubles
                pass
        return plan

    def generate_implementation_plan_markdown(
        self,
        plan: ArchitecturePlan,
        trace_id: str,
        product_id: str,
        spec_text: str,
        build_plan: Optional[SequencedBuildPlan] = None,
    ) -> tuple[str, str]:
        """Synthesizes a standardized, production-grade 7-section Implementation Plan conforming to docs/planning/ standard."""
        import re
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        date_str = now.strftime("%Y-%m-%d")
        clean_pid = product_id.lower().replace("_", "-")

        # Determine deterministic plan filename
        lower_spec = (spec_text or "").lower()
        if build_plan:
            is_initial = (build_plan.build_type == "INITIAL_BUILD")
        else:
            is_initial = any(k in lower_spec for k in ["initial", "baseline", "greenfield", "create workload", "new workload"]) or (not lower_spec)

        if is_initial:
            filename = "0001-initial-workload-architecture.md"
            title = f"Initial Workload Architecture for {product_id}"
        elif any(k in lower_spec for k in ["refactor", "cleanup", "upgrade", "modernize"]):
            slug = re.sub(r'[^a-z0-9]+', '-', lower_spec[:40]).strip('-') or "modernization"
            filename = f"{date_str}-refactor-{slug}.md"
            title = f"Refactor: {plan.summary or slug}"
        elif any(k in lower_spec for k in ["fix", "bug", "hotfix", "patch", "repair"]):
            slug = re.sub(r'[^a-z0-9]+', '-', lower_spec[:40]).strip('-') or "defect-fix"
            filename = f"{date_str}-fix-{slug}.md"
            title = f"Fix: {plan.summary or slug}"
        else:
            slug = re.sub(r'[^a-z0-9]+', '-', lower_spec[:40]).strip('-') or "feature"
            filename = f"{date_str}-feat-{slug}.md"
            title = f"Feature: {plan.summary or slug}"

        plan_file_path = f"docs/planning/{filename}"

        # Collect Acceptance Criteria
        criteria = []
        if build_plan:
            for s in build_plan.steps:
                for c in s.acceptance_criteria:
                    if c not in criteria:
                        criteria.append(c)
        if not criteria:
            for t in plan.code_tasks + plan.infra_tasks:
                for c in t.acceptance_criteria:
                    if c not in criteria:
                        criteria.append(c)
        if not criteria:
            criteria = ["FastAPI microservice returns 200 OK on health endpoints", "Cloud Run container passes startup probe on port 8080", "Automated unit tests pass with zero errors"]

        criteria_md = "\n".join(f"- [ ] **{c}**" for c in criteria)

        # Collect APIs
        apis = (build_plan.required_cloud_apis if build_plan else []) or ["run.googleapis.com", "firestore.googleapis.com", "artifactregistry.googleapis.com", "iam.googleapis.com"]
        apis_md = "\n".join(f"- `{api}`" for api in sorted(set(apis)))

        # Collect Component Manifest
        manifest_rows = []
        if build_plan:
            for s in build_plan.steps:
                action = "[NEW]" if "DOCS" not in s.step_id else "[MODIFY]"
                for f in s.target_files:
                    manifest_rows.append(f"| `{action}` | `{f}` | {s.title} |")
        if not manifest_rows:
            manifest_rows = [
                f"| `[NEW]` | `apps/{clean_pid}/main.py` | Core FastAPI application router and handlers. |",
                f"| `[NEW]` | `apps/{clean_pid}/requirements.txt` | Python runtime dependencies. |",
                f"| `[NEW]` | `infra/workload/main.tf` | Declarative Cloud Run and Firestore Terraform resources. |",
                f"| `[NEW]` | `tests/test_main.py` | Pytest unit test coverage. |",
            ]
        manifest_md = "\n".join(dict.fromkeys(manifest_rows))

        # Sequenced Build Plan Steps
        steps_md = []
        if build_plan and build_plan.steps:
            for s in build_plan.steps:
                deps_str = ", ".join(s.depends_on) if s.depends_on else "None (Initial Foundation)"
                steps_md.append(
                    f"### Step {s.step_index}: {s.title} (`{s.step_id}`)\n"
                    f"- **Category**: `{s.category.value if hasattr(s.category, 'value') else str(s.category)}`\n"
                    f"- **Target Files**: {', '.join(f'`{f}`' for f in s.target_files)}\n"
                    f"- **Prerequisites**: {deps_str}\n"
                    f"- **Description**: {s.description}\n"
                )
        else:
            steps_md.append("1. **STEP-01 (FOUNDATION_API)**: Enable necessary Cloud APIs.\n2. **STEP-02 (STORAGE)**: Provision Firestore Database.\n3. **STEP-03 (IAM)**: Create Workload Service Account.\n4. **STEP-04 (APP_CODE)**: Implement FastAPI microservice.\n5. **STEP-05 (COMPUTE)**: Deploy Cloud Run v2 container.\n6. **STEP-06 (TEST)**: Execute pytest test suite.")

        steps_joined = "\n".join(steps_md)

        tier_desc = "Autonomous Code & Standard Infra" if plan.project_tier <= 2 else "Human-in-the-Loop Approval Required"
        approved_by = "Autonomous Tier 1/2 Policy" if plan.project_tier <= 2 else "Workload Manager / Admin Approval"

        markdown_doc = f"""---
title: "{title}"
product_id: "{clean_pid}"
trace_id: "{trace_id}"
date: "{date_str}"
tier: {plan.project_tier}
status: "PLANNED"
author: "StackVend Autonomous Engineering Pipeline"
reviewers: ["Architect Agent", "Compliance Agent", "QA Agent"]
approved_by: "{approved_by}"
---

# Implementation Plan: {title}

## 1. Executive Summary & Requirements
- **Problem Statement**: {plan.summary}
- **Business Justification**: Delivers self-contained, enterprise-grade cloud capability for `{product_id}` within StackVend.
- **Acceptance Criteria**:
{criteria_md}

## 2. Architecture & Topology Design
- **System Architecture**: {plan.architecture_overview}
- **Topology Diagram**:
```mermaid
graph TD
    Client[Client Traffic] -->|HTTP / TLS| Run[Cloud Run v2 Microservice]
    Run -->|Native SDK| DB[(Firestore Database)]
    Run -->|OIDC Auth| WIF[Workload Identity Federation]
    Run -->|Structured Logs| Logs[Google Cloud Logging]
```
- **Google Cloud APIs Required**:
{apis_md}

## 3. Security, IAM & Governance Assessment
- **Identity & Service Accounts**: Dedicated workload identity `sa-{clean_pid}@{self.project_id or 'project-id'}.iam.gserviceaccount.com`.
- **Least-Privilege Roles Granted**: Roles scoped strictly to runtime operations (`roles/datastore.user`, `roles/logging.logWriter`).
- **CMEK & Data Protection**: Standard Google-managed encryption keys with Cloud KMS CMEK evaluated during compliance review.
- **Governance Tier**: Tier {plan.project_tier} ({tier_desc}).
- **Risk Assessment**: {plan.risk_assessment}

## 4. Component Manifest & Proposed Changes
| Action | Path | Description |
| :--- | :--- | :--- |
{manifest_md}

## 5. Sequenced Build Plan (Task DAG)
{steps_joined}

## 6. Verification & Automated Test Strategy
- **Automated Unit Tests**: Pytest suites verifying route handlers, models, and business logic with mock fixtures.
- **Container Health & Probe Checks**: Cloud Run startup probe checking TCP port 8080.
- **CI/CD Validation**: GitHub Actions workflow deployment run verification.

## 7. Rollback & Blast Radius Assessment
- **Blast Radius**: Isolated entirely to the `{product_id}` workload namespace. No shared infrastructure or platform dependencies affected.
- **Rollback Procedure**: Revert git commit on `main` or trigger automated redeployment from prior healthy revision.
"""
        return plan_file_path, markdown_doc

    def persist_implementation_plan_to_firestore(self, product_id: str, plan_file_path: str, plan_markdown: str, trace_id: str) -> bool:
        """Persists implementation plan record to Firestore for fast retrieval by Flight Deck UI."""
        try:
            from datetime import datetime, timezone
            now_iso = datetime.now(timezone.utc).isoformat()
            filename = os.path.basename(plan_file_path)
            record = {
                "product_id": product_id,
                "plan_filename": filename,
                "plan_file_path": plan_file_path,
                "trace_id": trace_id,
                "created_at": now_iso,
                "status": "PLANNED",
                "markdown": plan_markdown,
            }
            if self.project_id:
                from google.cloud import firestore
                db = firestore.Client(project=self.project_id)
                db.collection("workloads").document(product_id).collection("implementation_plans").document(filename).set(record, merge=True)
                db.collection("implementation_plans").document(f"{product_id}_{filename}").set(record, merge=True)
                logger.info(f"Persisted Implementation Plan '{filename}' to Firestore for workload '{product_id}'")
                return True
        except Exception as e:
            logger.warning(f"Could not persist implementation plan to Firestore: {e}")
        return False

    def persist_build_plan_to_firestore(self, plan: SequencedBuildPlan) -> bool:
        """Persists the sequenced DAG build plan into Firestore under build_plans and workload history."""
        try:
            from google.cloud import firestore
            db = firestore.Client(project=self.project_id) if self.project_id else None
            if db:
                doc_data = plan.model_dump()
                # 1. Global collection indexed by trace_id
                db.collection("build_plans").document(plan.trace_id).set(doc_data)
                # 2. Workload subcollection history
                db.collection("workloads").document(plan.product_id).collection("build_plans").document(plan.trace_id).set(doc_data)
                logger.info(f"Persisted Sequenced Build Plan '{plan.plan_id}' with {plan.total_steps} steps to Firestore for workload '{plan.product_id}'")
                return True
        except Exception as e:
            logger.warning(f"Could not persist build plan to Firestore: {e}")
        return False

    def _generate_sequenced_build_plan(self, product_id: str, trace_id: str, spec_text: str, assigned_cidr: Optional[str] = None) -> SequencedBuildPlan:
        """Constructs an adaptive, topologically ordered build plan based on exact workload requirements."""
        import re
        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        clean_pid = product_id.lower().replace("_", "-")
        lower_spec = spec_text.lower()

        # 1. Feature detection
        is_blank_shell = any(k in lower_spec for k in ["blank", "empty", "no resources", "shell only", "baseline only"])
        needs_firestore = any(k in lower_spec for k in ["firestore", "database", "datastore", "collection", "db"])
        needs_compute = (not is_blank_shell) and (any(k in lower_spec for k in ["run", "compute", "fastapi", "service", "api", "endpoint", "flask", "server", "web", "http"]) or needs_firestore)
        needs_pubsub = any(k in lower_spec for k in ["pubsub", "pub/sub", "topic", "queue", "messaging"])
        needs_storage = any(k in lower_spec for k in ["bucket", "gcs", "cloud storage", "blob"])
        needs_registry = needs_compute or ("docker" in lower_spec) or ("artifact registry" in lower_spec)
        needs_vpc = bool(assigned_cidr) or any(k in lower_spec for k in ["vpc", "subnet", "connector", "vpc access", "private ip", "cloud sql", "redis memory"])

        # Extract seed emails if requested
        seed_email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', spec_text)
        seed_email = seed_email_match.group(0) if seed_email_match else None

        # 2. Dynamic Required Cloud APIs
        required_apis = ["cloudresourcemanager.googleapis.com", "iam.googleapis.com"]
        if needs_compute:
            required_apis.append("run.googleapis.com")
        if needs_firestore:
            required_apis.append("firestore.googleapis.com")
        if needs_registry:
            required_apis.append("artifactregistry.googleapis.com")
            required_apis.append("cloudbuild.googleapis.com")
        if needs_pubsub:
            required_apis.append("pubsub.googleapis.com")
        if needs_storage:
            required_apis.append("storage.googleapis.com")
        if needs_vpc:
            # Row IPAM-1: no fallback range literal when IPAM assigned none (invariant 3); see the STEP-VPC text below.
            required_apis.append("vpcaccess.googleapis.com")
            required_apis.append("compute.googleapis.com")

        steps: List[BuildPlanStep] = []
        last_step_id = None

        if is_blank_shell:
            steps.append(BuildPlanStep(
                step_id="STEP-01-SCAFFOLD",
                step_index=1,
                category=BuildStepCategory.FOUNDATION_API,
                title="Initialize Workload Repository & Terraform Baseline",
                target_files=["infra/workload/main.tf", "infra/workload/variables.tf", "infra/workload/outputs.tf"],
                description=f"Provision $0 baseline shell repository and Terraform scaffolding for {product_id}.",
                acceptance_criteria=["Valid Terraform files with zero compute resources"],
                depends_on=[],
                status=BuildStepStatus.PENDING,
            ))
            steps.append(BuildPlanStep(
                step_id="STEP-02-DOCS",
                step_index=2,
                category=BuildStepCategory.DOCS,
                title="Generate Workload Documentation",
                target_files=["README.md"],
                description=f"Document repository structure and usage for {product_id}.",
                acceptance_criteria=["README.md documents baseline architecture"],
                depends_on=["STEP-01-SCAFFOLD"],
                status=BuildStepStatus.PENDING,
            ))
        else:
            # Stage 1: APIs
            step_apis_id = "STEP-01-APIS"
            steps.append(BuildPlanStep(
                step_id=step_apis_id,
                step_index=len(steps) + 1,
                category=BuildStepCategory.FOUNDATION_API,
                title="Enable Google Cloud Foundation APIs",
                target_files=["infra/workload/main.tf"],
                description=f"Enable required APIs ({', '.join(required_apis)}) via google_project_service.",
                acceptance_criteria=["APIs declared with project = var.project_id and disable_on_destroy = false"],
                depends_on=[],
                status=BuildStepStatus.PENDING,
            ))
            last_step_id = step_apis_id

            # Stage 1b: VPC & Serverless Connector if required
            if needs_vpc:
                step_vpc_id = "STEP-VPC"
                steps.append(BuildPlanStep(
                    step_id=step_vpc_id,
                    step_index=len(steps) + 1,
                    category=BuildStepCategory.FOUNDATION_API,
                    title="Provision Isolated VPC & Serverless VPC Access Connector",
                    target_files=["infra/workload/vpc.tf", "infra/workload/variables.tf"],
                    description=(
                        f"Provision isolated VPC network and Serverless VPC Access Connector with assigned IPAM CIDR block (ip_cidr_range = '{assigned_cidr}')."
                        if assigned_cidr else
                        "Provision isolated VPC network and Serverless VPC Access Connector; ip_cidr_range = var.connector_cidr (the platform IPAM range, supplied in terraform.tfvars; never a CIDR literal)."
                    ),
                    acceptance_criteria=["VPC network and Serverless VPC Connector declared with assigned CIDR", "variables.tf parameterizes ip_cidr_range"],
                    depends_on=[last_step_id],
                    status=BuildStepStatus.PENDING,
                ))
                last_step_id = step_vpc_id

            # Stage 2: Database / Storage
            if needs_firestore:
                step_db_id = "STEP-02-DATABASE"
                steps.append(BuildPlanStep(
                    step_id=step_db_id,
                    step_index=len(steps) + 1,
                    category=BuildStepCategory.DATABASE,
                    title="Provision Firestore Native Database",
                    target_files=["infra/workload/main.tf"],
                    description="Create google_firestore_database (default) in FIRESTORE_NATIVE mode.",
                    acceptance_criteria=["Firestore Native DB declared with depends_on = [google_project_service.apis]"],
                    depends_on=[last_step_id],
                    status=BuildStepStatus.PENDING,
                ))
                last_step_id = step_db_id

            if needs_storage:
                step_storage_id = "STEP-STORAGE"
                steps.append(BuildPlanStep(
                    step_id=step_storage_id,
                    step_index=len(steps) + 1,
                    category=BuildStepCategory.DATABASE,
                    title="Provision Cloud Storage Buckets",
                    target_files=["infra/workload/main.tf"],
                    description=f"Provision Cloud Storage bucket for {product_id} storage.",
                    acceptance_criteria=["GCS bucket configured with uniform bucket-level access"],
                    depends_on=[step_apis_id],
                    status=BuildStepStatus.PENDING,
                ))
                last_step_id = step_storage_id

            # Stage 3: Registry & IAM
            if needs_registry:
                step_reg_id = "STEP-REGISTRY"
                steps.append(BuildPlanStep(
                    step_id=step_reg_id,
                    step_index=len(steps) + 1,
                    category=BuildStepCategory.REGISTRY,
                    title="Provision Artifact Registry Container Repository",
                    target_files=["infra/workload/main.tf"],
                    description=f"Create Docker artifact registry repository 'castor-{clean_pid}'.",
                    acceptance_criteria=["google_artifact_registry_repository declared with format = 'DOCKER'"],
                    depends_on=[step_apis_id],
                    status=BuildStepStatus.PENDING,
                ))

            step_iam_id = "STEP-IAM"
            steps.append(BuildPlanStep(
                step_id=step_iam_id,
                step_index=len(steps) + 1,
                category=BuildStepCategory.IAM,
                title="Provision Workload Service Account & Scoped IAM Bindings",
                target_files=["infra/workload/main.tf"],
                description=f"Create dedicated service account 'sa-castor-{clean_pid[:20]}' with least privilege permissions.",
                acceptance_criteria=["Service account declared with minimal necessary IAM role bindings"],
                depends_on=[last_step_id],
                status=BuildStepStatus.PENDING,
            ))
            last_step_id = step_iam_id

            # Stage 4: App Code & Compute (if compute requested). PLAN-CONTRACT-CHECK §3.2: no CICD step. The platform
            # renders the CI on both providers and builds every image with Buildpacks; a repository `cloudbuild.yaml`
            # (GitHub) and any Dockerfile are deleted before commit, so a step targeting one could never be met.
            if needs_compute:
                step_code_id = "STEP-APP-CODE"
                steps.append(BuildPlanStep(
                    step_id=step_code_id,
                    step_index=len(steps) + 1,
                    category=BuildStepCategory.APP_CODE,
                    title="Implement Application Code & Buildpack Definitions",
                    target_files=["main.py", "requirements.txt", "Procfile", ".python-version"],
                    description=(
                        f"Implement application endpoints, data models, seed user '{seed_email}', and Procfile for Google Cloud Buildpacks."
                        if seed_email
                        else "Implement application endpoints, data models, and Procfile for Google Cloud Buildpacks."
                    ),
                    acceptance_criteria=["FastAPI app functional", "Procfile entrypoint configured", "Dependencies pinned"],
                    depends_on=[step_iam_id],
                    status=BuildStepStatus.PENDING,
                ))

                step_compute_id = "STEP-COMPUTE"
                steps.append(BuildPlanStep(
                    step_id=step_compute_id,
                    step_index=len(steps) + 1,
                    category=BuildStepCategory.COMPUTE,
                    title="Provision Cloud Run v2 Compute Service",
                    target_files=["infra/workload/main.tf", "infra/workload/variables.tf", "infra/workload/outputs.tf"],
                    description=f"Provision Cloud Run v2 service bound to workload SA with public invoker IAM.",
                    acceptance_criteria=["Cloud Run service declared with depends_on=[google_project_service.apis]"],
                    depends_on=[step_iam_id, step_code_id],
                    status=BuildStepStatus.PENDING,
                ))

                step_test_id = "STEP-TESTS"
                steps.append(BuildPlanStep(
                    step_id=step_test_id,
                    step_index=len(steps) + 1,
                    category=BuildStepCategory.TEST,
                    title="Implement Pytest Unit Test Suite",
                    target_files=["tests/test_main.py", "README.md"],
                    description="Write comprehensive pytest unit tests verifying endpoints and business logic.",
                    acceptance_criteria=["All pytest tests pass", "README documents API endpoints"],
                    depends_on=[step_code_id],
                    status=BuildStepStatus.PENDING,
                ))
            else:
                steps.append(BuildPlanStep(
                    step_id="STEP-DOCS",
                    step_index=len(steps) + 1,
                    category=BuildStepCategory.DOCS,
                    title="Generate Architecture Documentation",
                    target_files=["README.md"],
                    description="Document cloud infrastructure topology and configuration parameters.",
                    acceptance_criteria=["README.md documents all provisioned cloud resources"],
                    depends_on=[last_step_id],
                    status=BuildStepStatus.PENDING,
                ))

        # Re-index all steps strictly 1..N
        for idx, s in enumerate(steps, start=1):
            s.step_index = idx

        return SequencedBuildPlan(
            plan_id=f"plan-{trace_id[:8]}",
            product_id=product_id,
            trace_id=trace_id,
            build_type="INITIAL_BUILD",
            title=f"Autonomous Build Plan for {product_id}",
            summary=f"Topologically sequenced 7-step architecture plan for {product_id}",
            created_at=now_iso,
            total_steps=len(steps),
            status="PLANNED",
            required_cloud_apis=["run.googleapis.com", "firestore.googleapis.com", "cloudbuild.googleapis.com", "artifactregistry.googleapis.com", "iam.googleapis.com"],
            steps=steps,
        )

    def _fallback_plan(self, product_id: str, spec_text: str) -> ArchitecturePlan:
        """Deterministic fallback plan used when Vertex AI is uninitialized or in test mode."""
        return ArchitecturePlan(
            product_id=product_id,
            project_tier=1,
            summary=f"Automated execution plan for {product_id}",
            architecture_overview="Microservice architecture deployed to Cloud Run with Firestore storage.",
            infra_tasks=[
                TaskItem(
                    task_id="INFRA-01",
                    title="Provision Cloud Run Service & Firestore State",
                    category=TaskCategory.INFRA,
                    target_files=["infra/workload/main.tf", "infra/workload/custom.tf"],
                    description=f"Configure Terraform resources for {product_id} Cloud Run service.",
                    acceptance_criteria=["Valid HCL syntax", "Zero destructive changes"],
                    depends_on=[],
                    assigned_agent="gcp-devops",
                    priority=TaskPriority.HIGH,
                )
            ],
            code_tasks=[
                TaskItem(
                    task_id="CODE-01",
                    title="Implement Core Application Service & API Routes",
                    category=TaskCategory.CODE,
                    target_files=[f"apps/{product_id}/main.py", f"apps/{product_id}/requirements.txt"],
                    description=f"Develop FastAPI endpoints matching specification for {product_id}.",
                    acceptance_criteria=["Endpoints return 200 OK", "Passes input validation"],
                    depends_on=["INFRA-01"],
                    assigned_agent="developer",
                    priority=TaskPriority.HIGH,
                ),
                TaskItem(
                    task_id="TEST-01",
                    title="Implement Unit and Integration Test Suite",
                    category=TaskCategory.TEST,
                    target_files=[f"apps/{product_id}/test_main.py"],
                    description=f"Write pytest test cases with >85% code coverage for {product_id}.",
                    acceptance_criteria=["All pytest tests pass", "Coverage >= 85%"],
                    depends_on=["CODE-01"],
                    assigned_agent="developer",
                    priority=TaskPriority.MEDIUM,
                ),
            ],
            estimated_complexity="MEDIUM",
            requires_human_approval=False,
            risk_assessment="Low risk autonomous microservice deployment.",
        )
