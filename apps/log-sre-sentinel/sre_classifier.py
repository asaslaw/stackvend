"""
StackVend log SRE sentinel: incident classification (Wave 2 lane 14 PR-2, owner register row 24, plan
docs/planning/wave2-lane14-core-services-plan.md section 2.5 items 2-3).

Every decision here is an exact comparison on a structured Cloud Logging field: the entry's ``resource.type`` (dict
lookup), ``logName`` split positionally, ``resource.labels`` / entry ``labels`` read by exact key. There is no
substring, prefix, keyword or regex matching anywhere in this module (AGENTS.md invariant 2); the substring maps the
sentinel used before PR-2 are gone.

Pure functions only: no I/O. The caller (``sentinel.py``) supplies the host identity, the platform component sets and
a product resolver, and does the recording / dispatch.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Optional, Tuple

# ---------------------------------------------------------------------------------------------------------------
# Resource types (exact strings, Cloud Logging monitored-resource types)
# ---------------------------------------------------------------------------------------------------------------
WORKFLOWS_RESOURCE_TYPE = "workflows.googleapis.com/Workflow"
CLOUD_RUN_REVISION = "cloud_run_revision"
CLOUD_RUN_JOB = "cloud_run_job"

# Resource types a managed workload (child project) can emit errors from (plan section 2.5 item 2; lane 5's folder
# sink filter uses the same set).
WORKLOAD_RESOURCE_TYPES: FrozenSet[str] = frozenset({
    CLOUD_RUN_REVISION,
    CLOUD_RUN_JOB,
    "k8s_container",
    "gce_instance",
    "cloudsql_database",
})

# Every workload resource type above carries a ``project_id`` resource label. Workflows entries do NOT (their
# ``resource_container`` label is the project NUMBER, plan G6).
PROJECT_LABELED_TYPES: FrozenSet[str] = WORKLOAD_RESOURCE_TYPES

# Label keys (pinned by the fixture test, tests/fixtures/lane14_sentinel/).
WORKFLOW_ID_LABEL = "workflow_id"
RESOURCE_CONTAINER_LABEL = "resource_container"
WORKFLOW_EXECUTION_ID_ENTRY_LABEL = "workflows.googleapis.com/execution_id"
RUN_SERVICE_NAME_LABEL = "service_name"
RUN_JOB_NAME_LABEL = "job_name"
RUN_EXECUTION_NAME_ENTRY_LABEL = "run.googleapis.com/execution_name"
PROJECT_ID_LABEL = "project_id"

# The sentinel's own service name (REQUIRED_COMPONENTS.md). Its own errors are recorded, never dispatched (self-loop).
SENTINEL_SERVICE_NAME = "log-sre-sentinel-service"

# ---------------------------------------------------------------------------------------------------------------
# Default platform component sets. Authoritative values come from env PLATFORM_SERVICES / PLATFORM_JOBS (lane 5 I2,
# JSON from the exact keys of local.cloud_run_services / local.cloud_run_jobs). Until that env exists on an install
# the sentinel uses these sets, which tests/test_lane14_sentinel.py pins to infra/platform/main.tf so they cannot
# drift silently.
# ---------------------------------------------------------------------------------------------------------------
DEFAULT_PLATFORM_SERVICES: FrozenSet[str] = frozenset({
    "spec-ingestion-service",
    "orchestrator-gateway-service",
    "mcp-terraform-server",
    "mcp-kubernetes-server",
    "mcp-gcloud-server",
    "mcp-github-toolserver",
    "mcp-workspace-connector",
    "mcp-infracost-server",
    "mcp-compliance-server",
    "project-repo-vending-service",
    "log-sre-sentinel-service",
    "mcp-agent-builder-server",
    "product-control-center-ui",
    "castor-git-server",
})
DEFAULT_PLATFORM_JOBS: FrozenSet[str] = frozenset({
    "github-refactor-scanner-job",
    "qa-sandbox-test-runner",
    "finops-budget-enforcer-job",
    "infra-rollback-job",
    "sandbox-garbage-collector-job",
    "sre-telemetry-digest-job",
    "finops-spend-sync-job",
    "sandbox-workload-sweeper-job",
    "billing-alert-drain-job",
    "tf-applier",
})

# Source directory of each platform component, for the RCA "affected_repository" field (exact dict, replaces the
# substring map). Unknown -> "" (no guess).
PLATFORM_SOURCE_DIRS: Dict[str, str] = {
    "spec-ingestion-service": "apps/spec-ingestion/",
    "orchestrator-gateway-service": "apps/orchestrator-gateway/",
    "mcp-terraform-server": "mcp-servers/terraform/",
    "mcp-kubernetes-server": "mcp-servers/kubernetes/",
    "mcp-gcloud-server": "mcp-servers/gcloud/",
    "mcp-github-toolserver": "mcp-servers/github/",
    "mcp-workspace-connector": "mcp-servers/workspace/",
    "mcp-infracost-server": "mcp-servers/infracost/",
    "mcp-compliance-server": "mcp-servers/compliance/",
    "project-repo-vending-service": "apps/project-vending/",
    "log-sre-sentinel-service": "apps/log-sre-sentinel/",
    "mcp-agent-builder-server": "mcp-servers/agent-builder/",
    "product-control-center-ui": "apps/control-center/",
    "castor-git-server": "apps/git-server/",
    "github-refactor-scanner-job": "apps/refactor-scanner/",
    "qa-sandbox-test-runner": "apps/qa-runner/",
    "finops-budget-enforcer-job": "apps/finops-enforcer/",
    "infra-rollback-job": "apps/infra-rollback/",
    "sandbox-garbage-collector-job": "apps/sandbox-cleaner/",
    "sre-telemetry-digest-job": "apps/sre-digest/",
    "finops-spend-sync-job": "apps/finops-spend-sync/",
    "sandbox-workload-sweeper-job": "apps/sandbox-sweeper/",
    "billing-alert-drain-job": "apps/billing-alert-drain/",
    "tf-applier": "mcp-servers/terraform/",
}

# ---------------------------------------------------------------------------------------------------------------
# Outcomes
# ---------------------------------------------------------------------------------------------------------------
WORKLOAD_INCIDENT = "WORKLOAD_INCIDENT"
PLATFORM_INCIDENT = "PLATFORM_INCIDENT"
UNATTRIBUTED = "UNATTRIBUTED"

KIND_SRE_WORKFLOW = "sre_workflow"
KIND_PIPELINE = "pipeline"
KIND_SERVICE = "service"
KIND_JOB = "job"
KIND_WORKLOAD = "workload"

# UNATTRIBUTED reasons
R_LOGNAME_MALFORMED = "LOGNAME_MALFORMED"
R_UNKNOWN_RESOURCE_TYPE = "UNKNOWN_RESOURCE_TYPE"
R_PROJECT_LABEL_MISMATCH = "PROJECT_LABEL_MISMATCH"
R_HOST_NUMBER_UNRESOLVED = "HOST_NUMBER_UNRESOLVED"
R_RESOURCE_CONTAINER_MISMATCH = "RESOURCE_CONTAINER_MISMATCH"
R_WORKFLOW_OUTSIDE_HOST = "WORKFLOW_OUTSIDE_HOST"
R_UNKNOWN_HOST_SERVICE = "UNKNOWN_HOST_SERVICE"
R_UNKNOWN_HOST_JOB = "UNKNOWN_HOST_JOB"
R_HOST_RESOURCE_NOT_PLATFORM = "HOST_RESOURCE_NOT_PLATFORM"
R_HOST_UNCONFIGURED = "HOST_PROJECT_UNCONFIGURED"
# Product resolution reasons are passed through from the resolver (e.g. PRODUCT_NOT_IN_LEDGER, PRODUCT_AMBIGUOUS).


@dataclass
class Classification:
    incident_class: str  # WORKLOAD_INCIDENT | PLATFORM_INCIDENT | UNATTRIBUTED
    kind: str = ""  # sre_workflow | pipeline | service | job | workload | ""
    reason: str = ""  # UNATTRIBUTED reason, "" otherwise
    resource_type: str = ""
    entry_project: str = ""
    product_id: str = ""
    component: str = ""  # service / job / workflow id (display + fingerprint scope)
    workflow_id: str = ""
    execution_id: str = ""  # Workflows execution id (entry label)
    job_name: str = ""
    execution_name: str = ""  # Cloud Run job execution name (entry label)
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HostIdentity:
    project_id: str
    project_number: Optional[str]  # None = unresolved (CRM projects.get failed or not yet run)
    sre_workflow_name: str
    platform_services: FrozenSet[str]
    platform_jobs: FrozenSet[str]


# A product resolver maps a child project id to (product_id, "") or ("", <reason code>). Exact lookups only.
ProductResolver = Callable[[str], Tuple[str, str]]


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def entry_project(entry: Dict[str, Any]) -> Optional[str]:
    """Project id from ``logName`` split positionally: exactly ``projects/<id>/logs/<log>`` (the log id is URL-encoded,
    so it holds no ``/``). Any other shape -> None. Never reads a ``project_id`` label (Workflows entries have none)."""
    log_name = _as_str(entry.get("logName"))
    parts = log_name.split("/")
    if len(parts) != 4 or parts[0] != "projects" or parts[2] != "logs" or not parts[1] or not parts[3]:
        return None
    return parts[1]


def _unattributed(reason: str, resource_type: str, project: str = "", **detail: Any) -> Classification:
    return Classification(incident_class=UNATTRIBUTED, reason=reason, resource_type=resource_type,
                          entry_project=project, detail=dict(detail))


def classify_entry(entry: Dict[str, Any], host: HostIdentity, resolve_product: ProductResolver) -> Classification:
    """One typed table, ``==`` / set membership only (plan section 2.5 item 2)."""
    resource = _as_dict(entry.get("resource"))
    resource_type = _as_str(resource.get("type"))
    rlabels = _as_dict(resource.get("labels"))
    elabels = _as_dict(entry.get("labels"))

    project = entry_project(entry)
    if project is None:
        return _unattributed(R_LOGNAME_MALFORMED, resource_type)
    if not host.project_id:
        return _unattributed(R_HOST_UNCONFIGURED, resource_type, project)

    is_host = project == host.project_id

    if resource_type in PROJECT_LABELED_TYPES and _as_str(rlabels.get(PROJECT_ID_LABEL)) != project:
        return _unattributed(R_PROJECT_LABEL_MISMATCH, resource_type, project,
                             label_project_id=_as_str(rlabels.get(PROJECT_ID_LABEL)))

    # --- Workflows (host project only; identity = logName project + resource_container == host project NUMBER) ---
    if resource_type == WORKFLOWS_RESOURCE_TYPE:
        if not is_host:
            return _unattributed(R_WORKFLOW_OUTSIDE_HOST, resource_type, project)
        if not host.project_number:
            return _unattributed(R_HOST_NUMBER_UNRESOLVED, resource_type, project)
        container = _as_str(rlabels.get(RESOURCE_CONTAINER_LABEL))
        if container != host.project_number:
            return _unattributed(R_RESOURCE_CONTAINER_MISMATCH, resource_type, project, resource_container=container)
        workflow_id = _as_str(rlabels.get(WORKFLOW_ID_LABEL))
        execution_id = _as_str(elabels.get(WORKFLOW_EXECUTION_ID_ENTRY_LABEL))
        kind = KIND_SRE_WORKFLOW if workflow_id == host.sre_workflow_name else KIND_PIPELINE
        return Classification(incident_class=PLATFORM_INCIDENT, kind=kind, resource_type=resource_type,
                              entry_project=project, component=workflow_id, workflow_id=workflow_id,
                              execution_id=execution_id)

    # --- Host-project Cloud Run service / job ---
    if is_host and resource_type == CLOUD_RUN_REVISION:
        service_name = _as_str(rlabels.get(RUN_SERVICE_NAME_LABEL))
        if service_name not in host.platform_services:
            return _unattributed(R_UNKNOWN_HOST_SERVICE, resource_type, project, service_name=service_name)
        return Classification(incident_class=PLATFORM_INCIDENT, kind=KIND_SERVICE, resource_type=resource_type,
                              entry_project=project, component=service_name)

    if is_host and resource_type == CLOUD_RUN_JOB:
        job_name = _as_str(rlabels.get(RUN_JOB_NAME_LABEL))
        if job_name not in host.platform_jobs:
            return _unattributed(R_UNKNOWN_HOST_JOB, resource_type, project, job_name=job_name)
        return Classification(incident_class=PLATFORM_INCIDENT, kind=KIND_JOB, resource_type=resource_type,
                              entry_project=project, component=job_name, job_name=job_name,
                              execution_name=_as_str(elabels.get(RUN_EXECUTION_NAME_ENTRY_LABEL)))

    if is_host:
        reason = R_HOST_RESOURCE_NOT_PLATFORM if resource_type in WORKLOAD_RESOURCE_TYPES else R_UNKNOWN_RESOURCE_TYPE
        return _unattributed(reason, resource_type, project)

    # --- Child project: workload resource types only, attributed by exact reverse ledger lookup ---
    if resource_type not in WORKLOAD_RESOURCE_TYPES:
        return _unattributed(R_UNKNOWN_RESOURCE_TYPE, resource_type, project)
    product_id, reason = resolve_product(project)
    if not product_id:
        return _unattributed(reason or "PRODUCT_UNRESOLVED", resource_type, project)
    component = (_as_str(rlabels.get(RUN_SERVICE_NAME_LABEL)) if resource_type == CLOUD_RUN_REVISION
                 else _as_str(rlabels.get(RUN_JOB_NAME_LABEL)) if resource_type == CLOUD_RUN_JOB else "")
    return Classification(incident_class=WORKLOAD_INCIDENT, kind=KIND_WORKLOAD, resource_type=resource_type,
                          entry_project=project, product_id=product_id, component=component,
                          job_name=_as_str(rlabels.get(RUN_JOB_NAME_LABEL)) if resource_type == CLOUD_RUN_JOB else "",
                          execution_name=(_as_str(elabels.get(RUN_EXECUTION_NAME_ENTRY_LABEL))
                                          if resource_type == CLOUD_RUN_JOB else ""))


def parse_project_number(crm_project_name: Any) -> Optional[str]:
    """CRM v3 ``projects.get`` returns ``name: "projects/<number>"``; split positionally, digits only."""
    parts = _as_str(crm_project_name).split("/")
    if len(parts) != 2 or parts[0] != "projects" or not parts[1].isdigit():
        return None
    return parts[1]


def run_record_collection(job_name: str) -> str:
    """Run-record collection of a day-2 job (plan section 2.0): ``<job>_runs/{CLOUD_RUN_EXECUTION}``."""
    return f"{job_name}_runs"
