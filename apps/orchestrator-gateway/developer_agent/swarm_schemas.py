"""
Project Castor: Developer Swarm Schemas and Invariants
Data models for the Lead Staff Developer and Phased Multi-Wave Junior Swarm.
"""

from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, model_validator

from .errors import SWARM_TOKEN_ENVELOPE_EXCEEDED, DeveloperStageError


class SwarmExecutionMode(str, Enum):
    SOLO_FAST_PATH = "SOLO_FAST_PATH"         # <= 3 files affected, simple modification
    STANDARD_SWARM = "STANDARD_SWARM"         # 4 to 12 files, 2-3 junior agents in 1-2 waves
    ENTERPRISE_SWARM = "ENTERPRISE_SWARM"     # 13+ files, multi-service / 90-page spec, 4-8 juniors across 3 waves


class JuniorPersona(str, Enum):
    BACKEND_ENGINEER = "BACKEND_ENGINEER"
    FRONTEND_ENGINEER = "FRONTEND_ENGINEER"
    IAC_ENGINEER = "IAC_ENGINEER"
    TEST_ENGINEER = "TEST_ENGINEER"
    DEVOPS_ENGINEER = "DEVOPS_ENGINEER"
    DATABASE_ENGINEER = "DATABASE_ENGINEER"


# Custom Exceptions for Distributed Guardrails
class ConflictingFileAssignmentError(Exception):
    """Raised when two junior tasks attempt to write to the same file path."""
    pass


class UnauthorizedFileCreationError(Exception):
    """Raised when a junior agent stages a file outside its assigned_files scope."""
    pass


class FinOpsCircuitBreakerError(DeveloperStageError):
    """Raised when cumulative swarm token consumption exceeds the allocated budget envelope.

    RT14-23 (owner 11-14): a typed developer stop (error_class SWARM_TOKEN_ENVELOPE_EXCEEDED). It was a plain
    Exception, so the handler's broad swarm `except` swallowed it and ran the unmetered single-turn build instead; as a
    DeveloperStageError it is re-raised there with the other typed stops and the run fails with its class."""

    def __init__(self, message: str = ""):
        super().__init__(SWARM_TOKEN_ENVELOPE_EXCEEDED, message)


class PoisonedContractEscalationError(Exception):
    """Raised when repeated self-healing retries fail due to an invalid frozen contract."""
    pass


class JuniorTaskAssignment(BaseModel):
    task_id: str = Field(..., description="Unique task identifier, e.g. 'task-backend-orders'")
    persona: JuniorPersona = Field(..., description="Assigned junior developer specialization")
    wave: int = Field(default=1, ge=1, le=4, description="Sequential execution wave (1=Foundation, 2=Services/UI, 3=QA/CI)")
    assigned_files: List[str] = Field(..., description="List of filepaths exclusively assigned to this worker (disjoint write scope)")
    read_dependencies: List[str] = Field(default_factory=list, description="Targeted files from prior waves whose content is injected into worker context")
    task_objective: str = Field(..., description="Clear, domain-specific instruction for this task")
    injected_contracts: Dict[str, Any] = Field(default_factory=dict, description="Frozen interface schemas (Pydantic / OpenAPI / HCL) relevant to this persona")
    specific_guardrails: List[str] = Field(default_factory=list, description="Persona-specific negative constraints and rules")
    iac_engine: Optional[str] = Field(default="OPENTOFU", description="'OPENTOFU' or 'TERRAFORM'")

    @model_validator(mode="after")
    def validate_zero_dockerfiles_in_assignment(self):
        for f in self.assigned_files:
            lower = f.lower()
            if "dockerfile" in lower or ".dockerignore" in lower:
                raise ValueError(
                    f"Platform Mandate Violation in {self.task_id}: Generating '{f}' is prohibited. "
                    "StackVend workloads strictly rely on Google Cloud Buildpacks (Zero Dockerfiles)."
                )
        return self


class LeadDeveloperDecompositionPlan(BaseModel):
    execution_mode: SwarmExecutionMode = Field(default=SwarmExecutionMode.STANDARD_SWARM)
    iac_engine: str = Field(default="OPENTOFU", description="'OPENTOFU' or 'TERRAFORM'")
    vcs_provider: str = Field(default="GITHUB", description="'GITHUB' or 'SERVERLESS_GIT'")
    max_swarm_token_envelope: int = Field(default=350_000, description="FinOps ceiling for total swarm input+output tokens")
    shared_contracts: Dict[str, Any] = Field(default_factory=dict, description="Common data contracts (Pydantic / OpenAPI / HCL signatures)")
    wave_0_contract_files: Dict[str, str] = Field(default_factory=dict, description="Wave 0 immutable interface schemas and contracts")
    tasks: List[JuniorTaskAssignment] = Field(default_factory=list, description="Ordered junior task assignments across waves")
    lead_notes: str = Field(default="", description="Staff Lead architectural synthesis notes and guidance")

    @model_validator(mode="after")
    def validate_disjoint_file_partitions(self):
        """Enforces that no two tasks in the decomposition share file ownership."""
        all_assigned: Dict[str, str] = {}
        for t in self.tasks:
            for f in t.assigned_files:
                if f in all_assigned:
                    prior_task = all_assigned[f]
                    raise ValueError(
                        f"WBS Invariant Violation: File '{f}' assigned to multiple tasks: '{prior_task}' and '{t.task_id}'. "
                        "All assigned_files partitions must be strictly disjoint."
                    )
                all_assigned[f] = t.task_id
        return self


class JuniorFilesEnvelope(BaseModel):
    """V6 (Step 1 S1-B, lane 8B §3): the JSON envelope every junior / repair response must be: {"files": {path: text}}.
    Validated on the same clean_json the swarm parser produces (Step 1 RT F13); extra keys are tolerated (models add
    commentary keys), a non-object `files` or a non-string file body is invalid."""
    files: Dict[str, str]


class JuniorExecutionResult(BaseModel):
    task_id: str
    persona: JuniorPersona
    wave: int
    files: Dict[str, str]
    consumed_tokens: int = 0
    duration_seconds: float = 0.0
    status: Literal["SUCCEEDED", "FAILED", "SELF_HEALING"] = "SUCCEEDED"
    error_message: Optional[str] = None
    rendered_prompt: Optional[str] = None
    # SLOW-CALL-FALLBACK (owner 11-13): the model that wrote these files, why the walk left the task's model (TIMEOUT /
    # TRANSIENT_<code>; None = no fallback) and every attempt (llm_transport.CallAttempt.to_dict)
    model: Optional[str] = None
    model_fallback_reason: Optional[str] = None
    model_attempts: List[Dict[str, Any]] = Field(default_factory=list)


class ContractAmendment(BaseModel):
    is_amended: bool
    amended_contracts: Dict[str, Any]
    remediation_notes: str
    retry_authorized: bool = True


# --- Swarm Flight Deck Telemetry Schemas ---

class JuniorExecutionTelemetry(BaseModel):
    task_id: str
    persona: str
    wave: int
    status: str = "PENDING"          # PENDING | RUNNING | SUCCEEDED | SELF_HEALING | FAILED
    elapsed_seconds: float = 0.0
    output_tokens: int = 0
    assigned_files: List[str] = Field(default_factory=list)
    retry_count: int = 0
    error_message: Optional[str] = None


class WaveExecutionTelemetry(BaseModel):
    wave_index: int
    wave_name: str
    status: str = "PENDING"          # PENDING | RUNNING | SUCCEEDED | FAILED
    elapsed_seconds: float = 0.0
    tasks: List[JuniorExecutionTelemetry] = Field(default_factory=list)


class DeveloperSwarmStageTelemetry(BaseModel):
    execution_mode: str = "STANDARD_SWARM"
    current_wave: int = 1
    total_waves: int = 3
    total_tokens_consumed: int = 0
    max_tokens_budget: int = 350_000
    circuit_breaker_tripped: bool = False
    waves: List[WaveExecutionTelemetry] = Field(default_factory=list)
    file_attribution: Dict[str, str] = Field(default_factory=dict)

