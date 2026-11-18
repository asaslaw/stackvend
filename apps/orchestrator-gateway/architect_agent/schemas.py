"""
Project Castor: Architect Agent Pydantic Schemas
Defines structured Task DAG models and Architecture Plan contracts.
"""

import re
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, get_args
from pydantic import BaseModel, Field, PrivateAttr, field_validator

try:  # lane 10 (FD-51): the typed per-service topology (root shared/ is the source; vendored into the gateway)
    from shared.service_topology import ServiceTopologyIntent
except ImportError:  # pragma: no cover - package-relative fallback
    from ..shared.service_topology import ServiceTopologyIntent  # type: ignore


# Primary compute archetypes (exact enum). Single source for the architect's LLM response schema; must equal
# developer_agent/compute_intent.py ARCHETYPES (tests/test_architect_compute_archetype.py guards the parity).
ComputeArchetype = Literal["cloudrun", "event-worker", "gke-autopilot", "gce-bastion", "foundation-only"]
COMPUTE_ARCHETYPES = tuple(get_args(ComputeArchetype))


class TaskCategory(str, Enum):
    CODE = "CODE"
    INFRA = "INFRA"
    TEST = "TEST"
    DOCS = "DOCS"
    RELEASE = "RELEASE"


class BuildStepCategory(str, Enum):
    FOUNDATION_API = "FOUNDATION_API"
    DATABASE = "DATABASE"
    REGISTRY = "REGISTRY"
    IAM = "IAM"
    APP_CODE = "APP_CODE"
    CICD = "CICD"
    COMPUTE = "COMPUTE"
    TEST = "TEST"
    DOCS = "DOCS"


class BuildStepStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class TaskPriority(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class TaskItem(BaseModel):
    task_id: str = Field(default="TASK-01", description="Unique task identifier, e.g. INFRA-01 or CODE-01")
    title: str = Field(default="Task", description="Short human-readable task title")
    category: TaskCategory = Field(default=TaskCategory.CODE, description="Category of the task")
    target_files: List[str] = Field(default_factory=list, description="Target file paths affected or created")
    description: str = Field(default="", description="Detailed engineering instructions for the assigned agent")
    acceptance_criteria: List[str] = Field(default_factory=list, description="Verifiable completion criteria")
    depends_on: List[str] = Field(default_factory=list, description="List of task_ids that must complete first")
    assigned_agent: str = Field(default="developer", description="Assigned persona: 'developer', 'gcp-devops', 'qa-reviewer', 'release-engineer'")
    priority: TaskPriority = Field(default=TaskPriority.MEDIUM)


class BuildPlanStep(BaseModel):
    step_id: str = Field(default="STEP-01", description="Unique build step identifier, e.g. STEP-01-APIS")
    step_index: int = Field(default=1, description="Topological 1-based execution index")
    category: BuildStepCategory = Field(default=BuildStepCategory.FOUNDATION_API, description="Build stage category")
    title: str = Field(default="Build Step", description="Human readable step title")
    target_files: List[str] = Field(default_factory=list, description="Files affected or generated in this step")
    description: str = Field(default="", description="Precise technical specification for this step")
    acceptance_criteria: List[str] = Field(default_factory=list, description="Criteria to verify step completion")
    depends_on: List[str] = Field(default_factory=list, description="List of prerequisite step_ids that must complete first")
    status: BuildStepStatus = Field(default=BuildStepStatus.PENDING)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    output_summary: Optional[str] = None


class SequencedBuildPlan(BaseModel):
    plan_id: Optional[str] = Field(default=None, description="Unique build plan identifier")
    product_id: Optional[str] = Field(default=None, description="Workload identifier")
    trace_id: Optional[str] = Field(default=None, description="Correlating workflow trace ID")
    build_type: Literal["INITIAL_BUILD", "FEATURE_REQUEST"] = Field(default="INITIAL_BUILD", description="'INITIAL_BUILD' or 'FEATURE_REQUEST'")
    feature_request_id: Optional[str] = Field(default=None, description="Linked feature request ID if applicable")
    title: str = Field(default="Workload Build Plan", description="Executive title of the build plan")
    summary: str = Field(default="Automated architecture build plan", description="Summary of architectural changes")
    created_at: Optional[str] = Field(default=None, description="ISO 8601 creation timestamp")
    total_steps: int = Field(default=0, description="Total number of sequenced build steps")
    status: Literal["PLANNED", "EXECUTING", "COMPLETED", "FAILED"] = Field(default="PLANNED", description="'PLANNED', 'EXECUTING', 'COMPLETED', 'FAILED'")
    required_cloud_apis: List[str] = Field(default_factory=list, description="Google Cloud APIs required by the architecture")
    steps: List[BuildPlanStep] = Field(default_factory=list, description="Topologically ordered build steps")


class ArchitecturePlanDAG(BaseModel):
    model_config = {
        "json_schema_extra": {
            "required": [
                "product_id",
                "summary",
                "architecture_overview",
                "infra_tasks",
                "code_tasks",
                "target_compute_services",
                "compute_archetype",
                "service_topology",
                "iac_engine",
            ]
        }
    }

    product_id: str = Field(default="workload", description="Normalized product identifier, e.g. customer-portal")
    project_tier: int = Field(default=1, description="Policy tier: 1 (Autonomous), 2 (Policy-bounded infra), 3 (HITL approval)")

    @field_validator("project_tier", mode="before")
    @classmethod
    def coerce_and_clamp_project_tier(cls, v: Any) -> int:
        """Coerce string/float inputs and clamp strictly to valid policy tiers 1, 2, or 3."""
        if v is None:
            return 1
        try:
            val = int(v)
            return min(max(val, 1), 3)
        except (ValueError, TypeError):
            return 1

    summary: str = Field(default="Architecture Plan", description="Executive summary of the requested change")
    architecture_overview: str = Field(default="Cloud Run and Firestore workload architecture", description="High-level architectural design and topology description")
    infra_tasks: List[TaskItem] = Field(default_factory=list, description="List of cloud infrastructure tasks for DevOps agent")
    code_tasks: List[TaskItem] = Field(default_factory=list, description="List of application code tasks for Developer agent")
    target_compute_services: List[str] = Field(
        default_factory=list,
        description="Explicit authoritative list of compute workload names (e.g. ['api', 'worker']). [0] is the workload the primary compute_archetype runs; [1:] are Cloud Run services. Defaults to [product_id] for single-service workloads; [] for foundation-only.",
    )
    # Typed primary compute kind (replaces the deleted spec-keyword detector HD-01). Exact enum: any other value fails
    # validation. Optional only so records written before this field (and the deterministic / Map-Reduce plans) keep
    # their meaning: None -> developer_agent/compute_intent.py uses the bundle_id table, then the Cloud Run contract.
    compute_archetype: Optional[ComputeArchetype] = Field(
        default=None,
        description=(
            "Primary compute kind, exactly one of: 'cloudrun' (HTTP-serving Cloud Run v2 service), 'event-worker' "
            "(Cloud Run Job fed by a Pub/Sub subscription, no HTTP ingress), 'gke-autopilot' (private GKE Autopilot "
            "cluster), 'gce-bastion' (Compute Engine VM reached over IAP SSH), 'foundation-only' (no compute at all)"
        ),
    )
    # Lane 10 (FD-51 / FD-50): every compute service with its own kind, the primary, the service-to-service calls and
    # the resources services read. Required in the LLM response schema; validated by the topology gate
    # (architect_agent/topology_gate.py), not by this model's parse: the handler keeps the raw value in
    # `_raw_service_topology`, so a malformed topology becomes diagnostics + one repair, never a plan-wide fallback.
    service_topology: Optional[ServiceTopologyIntent] = Field(
        default=None,
        description=(
            "Typed compute topology: services (name, kind, purpose), primary_service (its kind equals "
            "compute_archetype), acyclic edges (caller -> callee; http to cloudrun, pubsub to the event-worker, launch "
            "from a cloudrun service to a gce-worker) and "
            "resources with the env var each consumer reads"
        ),
    )
    _raw_service_topology: Any = PrivateAttr(default=None)
    _is_fallback: bool = PrivateAttr(default=False)
    _no_model_response: bool = PrivateAttr(default=False)   # lane 10 RT F7: no model answered at all (outage)
    sequenced_build_plan: Optional[SequencedBuildPlan] = Field(default=None, description="Detailed DAG build plan stored in Firestore")
    estimated_complexity: Literal["LOW", "MEDIUM", "HIGH"] = Field(default="MEDIUM", description="LOW, MEDIUM, or HIGH")
    requires_human_approval: bool = Field(default=False, description="True if Tier 3 HITL triggers are detected")
    risk_assessment: str = Field(default="Low risk; standard automated rollout.", description="Risk evaluation")
    requires_vpc: bool = Field(
        default=False,
        description="True if workload requires private VPC networking, Serverless VPC Access Connector, or private database access",
    )
    network_purpose: Optional[Literal["SERVERLESS_VPC_CONNECTOR", "WORKLOAD_SUBNET", "HYBRID"]] = Field(
        default=None,
        description="'SERVERLESS_VPC_CONNECTOR' | 'WORKLOAD_SUBNET' | 'HYBRID'",
    )
    assigned_cidr_block: Optional[str] = Field(
        default=None,
        description="Injected IPAM CIDR reservation (e.g. 10.100.1.0/28)",
    )
    bundle_id: Optional[Literal["secure-three-tier-web", "event-driven-microservice", "vertex-ai-rag-stack", "private-gke-microservices", "serverless-analytics-lakehouse"]] = Field(
        default=None,
        description="Selected Composite Solution Bundle ID (e.g. 'secure-three-tier-web')",
    )
    iac_engine: Literal["tofu", "terraform"] = Field(
        default="tofu",
        description="Target IaC execution engine ('tofu' or 'terraform')",
    )



class ArchitecturePlan(ArchitecturePlanDAG):
    plan_markdown: Optional[str] = Field(default="", description="Full markdown implementation plan adhering to docs/planning standard")
    plan_file_path: Optional[str] = Field(default="", description="Repository target path, e.g. docs/planning/YYYY-MM-DD-feat-<slug>.md")


COMPUTE_INTENT_RECORD_SCHEMA = "architect_compute_intent/v1"
# v2 (lane 10): the record also carries the validated `service_topology` (shared.service_topology record form).
COMPUTE_INTENT_RECORD_SCHEMA_V2 = "architect_compute_intent/v2"


def compute_intent_record(plan: Any, topology: Any = None,
                          provenance: Optional[Dict[str, Any]] = None,
                          plan_apis: Optional[List[str]] = None) -> Dict[str, Any]:
    """The plan's typed compute fields, as the record the developer consumes (HD-01/HD-02 replacement): the request
    body `architect_compute_intent` and Firestore `pipeline_executions/{trace}.architect_compute_intent`. Only typed
    fields are copied. `compute_archetype` is an exact enum: an unknown value raises (never copied, never defaulted).

    Lane 10: with a `topology` (shared.service_topology.ValidatedTopology from the architect's topology gate) the
    record is v2 and carries `service_topology` (data only: canonical intent + sha256). `target_compute_services` /
    `compute_archetype` are then the topology's own (primary first); the gate already refused a plan whose
    `compute_archetype` differs from the topology's primary kind."""
    data = plan.model_dump() if hasattr(plan, "model_dump") else dict(plan or {})
    tcs = data.get("target_compute_services")
    bundle = data.get("bundle_id")
    ca = data.get("compute_archetype")
    if ca is not None and ca not in COMPUTE_ARCHETYPES:
        raise ValueError(f"compute_archetype {ca!r} is not one of {list(COMPUTE_ARCHETYPES)}")
    record: Dict[str, Any] = {
        "schema": COMPUTE_INTENT_RECORD_SCHEMA,
        "target_compute_services": [str(x) for x in tcs] if isinstance(tcs, (list, tuple)) else [],
        "bundle_id": bundle if isinstance(bundle, str) else None,
        "compute_archetype": ca if isinstance(ca, str) else None,
    }
    if topology is not None:
        record["schema"] = COMPUTE_INTENT_RECORD_SCHEMA_V2
        record["target_compute_services"] = list(topology.names)
        record["compute_archetype"] = topology.archetype
        record["service_topology"] = topology.as_record()
        if provenance:
            record["topology_provenance"] = dict(provenance)
    if plan_apis is not None:
        # TI-3i (register, owner 10-21): the MODEL-written build plan's typed API list (the caller passes it only
        # when the model wrote the build plan, never the keyword fallback); exact API grammar, sorted, unique. The
        # developer reads it only to decide whether a typed-intent entry a repair removed was asked for.
        record["required_cloud_apis"] = sorted({a for a in plan_apis if isinstance(a, str)
                                                and re.fullmatch(r"[a-z][a-z0-9-]{0,62}\.googleapis\.com", a)})
    return record


class ArchitectDecompositionResult(BaseModel):
    trace_id: str
    product_id: str
    spec_doc_id: str
    architecture_plan: ArchitecturePlan
    task_dag: List[TaskItem]
    sequenced_build_plan: Optional[SequencedBuildPlan] = None
    infra_plan: Dict[str, Any]
    markdown_summary: str
    plan_markdown: Optional[str] = None
    plan_file_path: Optional[str] = None
    consensus_telemetry: Optional[Any] = None
    compute_intent: Optional[Dict[str, Any]] = None   # compute_intent_record(architecture_plan)
