"""
Project Castor: Workload Management & Lifecycle Routes
Handles catalog listing, feature requests, plan viewers, policies, budget ceilings, decommissioning, and redeployment.
"""

import base64
import concurrent.futures
from datetime import datetime, timedelta, timezone
import html
import io
import json
import logging
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid
import xml.etree.ElementTree as ET
import zipfile

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Request, Response, UploadFile
from authz import ADMIN, PLATFORM_PSEUDO_WORKLOADS, SCOPED, TRACE, WORKLOAD, WORKLOAD_CHILD, require
from fastapi.responses import JSONResponse

from auth import verify_admin_access, verify_workload_access
from config import ENVIRONMENT, PROJECT_ID, get_caller_main_module, github_owner, require_github_owner
from folders import FolderConfigError, is_descendant_of_root, managed_root_folder, normalize_folder_name
import destructive_actions
import identity
import workflow_executions as wfx
from shared import sandbox_sweep
from shared import build_admission as _build_admission  # BUILD-ADMISSION-QUEUE (G4)
from shared.path_safety import UnsafePathError, validate_product_id  # RT14-37
import build_queue
from compliance_label import compliance_label
from db import db, get_db, get_pubsub_publisher, get_storage
from routes.finops import calculate_run_rate_projection
from routes.settings import (
    GIT_SERVER_URL_UNKNOWN,
    get_git_server_url,
    get_platform_settings,
    get_vending_service_url,
    maintenance_refusal,
    make_vending_request,
    new_run_refusal,
    get_terraform_service_url,
    make_terraform_request,
)
# Lane 18 S2: project deletes (UI decommission, budget-breach decommission, sandbox sweep) are executed ONLY by
# project-vending behind its destructive guard; the CC mints approvals and calls vending (destructive_actions.py).
# The interim in-process sweep guard (sandbox_guard.py, lane 4) is superseded by vending's guard and is not called.

from schemas import PROFILE_ALLOWED_REGIONS, profile_is_downgrade
from shared.access_policy import (ACCESS_WIDENING_APPROVAL_FIELD, APP_ADMIN_CONTRACT_FIELD, SUBMITTER_PROVENANCE_FIELD,
                                  VERIFIED_SUBMITTER_FIELD, WideningChange, app_admin_list_digest,
                                  effective_app_admin_emails, platform_default_access_record, submitter_provenance,
                                  verified_submitter_member, widening_approval, workload_verified_submitter)
from schemas import (
    ArchiveWorkloadResponse,
    BuildPlanResponse,
    BuildPlanStepSummary,
    CreateFeatureRequest,
    CreateWorkloadRequest,
    DecommissionRequest,
    DecommissionResponse,
    DeployToFolderRequest,
    DeployedResource,
    ExtractedDocumentResponse,
    FeatureChangeType,
    FeatureRequestPriority,
    FeatureRequestRecord,
    RedeployRequestWithFolder,
    RedeployResponse,
    UpdateBudgetRequest,
    UpdateWorkloadAccessRequest,
    UpdateWorkloadPoliciesRequest,
    UpdateGitHubActionsDeployRequest,
    UserRole,
    access_record,
    access_widening,
    stored_access_policy,
    WorkloadBuildPlansResponse,
    WorkloadDetailsResponse,
    WorkloadPlanItem,
    WorkloadPlansResponse,
    WorkloadSummary,
    IaCDriftStatusResponse,
    IaCUpgradeHistoryResponse,
    IaCUpgradeRecord,
    TriggerIaCUpgradeRequest,
    ExtendSandboxRequest,
    ExtendSandboxResponse,
    PromoteSandboxResponse,
    ConfirmSandboxRequest,
    ConfirmSandboxResponse,
    SandboxSweepResult,
    UnarchiveWorkloadResponse,
    DeployInfraRequest,
    DeployInfraResponse,
)

try:
    from shared.sandbox_detection import (
        detect_sandbox_intent,
        compute_sandbox_expiry,
        compute_days_remaining,
        validate_extension,
        MAX_SANDBOX_CUMULATIVE_DAYS,
    )
except ImportError:
    try:
        from apps.control_center.shared.sandbox_detection import (
            detect_sandbox_intent,
            compute_sandbox_expiry,
            compute_days_remaining,
            validate_extension,
            MAX_SANDBOX_CUMULATIVE_DAYS,
        )
    except ImportError:
        from sandbox_detection import (  # type: ignore
            detect_sandbox_intent,
            compute_sandbox_expiry,
            compute_days_remaining,
            validate_extension,
            MAX_SANDBOX_CUMULATIVE_DAYS,
        )

try:
    from shared.iac_upgrade_engine import (
        inspect_workload_iac_drift,
        upgrade_workload_iac_vendoring,
        module_files_removed_by_upgrade,
        ModuleDeletionScopeError,
        record_iac_upgrade_start,
        record_iac_upgrade_complete,
        get_iac_upgrade_history,
    )
except ImportError:
    from iac_upgrade_engine import (  # type: ignore
        inspect_workload_iac_drift,
        upgrade_workload_iac_vendoring,
        module_files_removed_by_upgrade,
        ModuleDeletionScopeError,
        record_iac_upgrade_start,
        record_iac_upgrade_complete,
        get_iac_upgrade_history,
    )

try:
    from google.cloud import firestore
except ImportError:
    firestore = None

try:
    from google.cloud import storage
except ImportError:
    storage = None

try:
    from shared.github_identity import (GITHUB_ACTIONS_DEPLOY_FIELD, get_default_github_owner,
                                        github_actions_deploy_enabled, resolve_repo_identity)
except ImportError:
    try:
        from .github_identity import (GITHUB_ACTIONS_DEPLOY_FIELD, get_default_github_owner,
                                      github_actions_deploy_enabled, resolve_repo_identity)
    except ImportError:
        try:
            from github_identity import (GITHUB_ACTIONS_DEPLOY_FIELD, get_default_github_owner,
                                         github_actions_deploy_enabled, resolve_repo_identity)
        except ImportError:
            # GHA-DEPLOY-SWITCH unavailable: the switch cannot be read or written (typed refusals below).
            GITHUB_ACTIONS_DEPLOY_FIELD = "github_actions_deploy"
            github_actions_deploy_enabled = None
            def get_default_github_owner():  # FD-4AY: no built-in owner (shared.github_identity unavailable)
                owner = os.getenv('GITHUB_ORG') or os.getenv('GITHUB_DEPLOYMENTS_ORG') or os.getenv('GITHUB_OWNER')
                if not owner:
                    raise RuntimeError('No GitHub owner configured: set GITHUB_ORG')
                return owner
            def resolve_repo_identity(repo, default_owner=None, product_id=None):
                owner = default_owner or get_default_github_owner()
                if isinstance(repo, dict):
                    repo = repo.get('full_name') or repo.get('repo_name')
                if repo and '/' in repo:
                    parts = repo.split('/', 1)
                    return parts[0], parts[1], repo
                clean_pid = (product_id or 'workload').lower().replace('_', '-')
                repo_name = repo or clean_pid   # GITHUB-REPO-NAME-NO-PREFIX: shared default_repository_name
                return owner, repo_name, f'{owner}/{repo_name}'

try:
    from shared.vcs_provider import IncompleteRepoTreeError, VCSProviderFactory
except ImportError:
    try:
        from .vcs_provider import IncompleteRepoTreeError, VCSProviderFactory
    except ImportError:
        try:
            from vcs_provider import IncompleteRepoTreeError, VCSProviderFactory
        except ImportError:
            VCSProviderFactory = None

            class IncompleteRepoTreeError(RuntimeError):  # type: ignore[no-redef]
                """Stand-in when no VCS provider module exists (no tree can be read, so it is never raised)."""
                error_class = "REPO_TREE_INCOMPLETE"


def _repo_tree_incomplete(err: Exception, what: str) -> HTTPException:
    """FD-4DC: a reader that got a partial repository tree refuses with the typed class (HTTP 409); it never
    works on the part it could read. `what` says what was not done."""
    error_class = getattr(err, "error_class", None) or "REPO_TREE_INCOMPLETE"
    return HTTPException(status_code=409, detail=f"{error_class}: {err}. {what}")

try:
    from shared.express_synthesizer import (
        ExpressHCLSynthesizer, ExpressSynthesisRefused, express_name_suffix_plan, refuse_worker_renames,
        merge_name_plans, express_access_arguments, express_primary_service_output,
        EXPRESS_DEPLOYED_NAME_PLAN_FIELD, EXPRESS_NAME_PLAN_TRACKED_FIELD,
    )
except ImportError:
    try:
        from .shared.express_synthesizer import (
            ExpressHCLSynthesizer, ExpressSynthesisRefused, express_name_suffix_plan, refuse_worker_renames,
            merge_name_plans, express_access_arguments, express_primary_service_output,
            EXPRESS_DEPLOYED_NAME_PLAN_FIELD, EXPRESS_NAME_PLAN_TRACKED_FIELD,
        )
    except ImportError:
        try:
            from express_synthesizer import (
                ExpressHCLSynthesizer, ExpressSynthesisRefused, express_name_suffix_plan, refuse_worker_renames,
                merge_name_plans, express_access_arguments, express_primary_service_output,
                EXPRESS_DEPLOYED_NAME_PLAN_FIELD, EXPRESS_NAME_PLAN_TRACKED_FIELD,
            )
        except ImportError:
            ExpressHCLSynthesizer = None
            express_name_suffix_plan = None  # EXP-6: no synthesizer -> no rename check (synthesis fails closed anyway)
            refuse_worker_renames = None
            merge_name_plans = None
            express_access_arguments = None  # FD-4CS: no create-time check (synthesis fails closed anyway)
            express_primary_service_output = None  # no synthesizer -> no Express deploy reaches the URL step
            EXPRESS_DEPLOYED_NAME_PLAN_FIELD = "express_deployed_name_plan"
            EXPRESS_NAME_PLAN_TRACKED_FIELD = "express_name_plan_tracked"

            class ExpressSynthesisRefused(ValueError):  # no synthesizer: never raised
                reason = "EXPRESS_SYNTHESIS_REFUSED"

try:
    from shared.github_resilience import create_or_verify_branch
except ImportError:
    try:
        from .github_resilience import create_or_verify_branch
    except ImportError:
        try:
            from github_resilience import create_or_verify_branch
        except ImportError:
            def create_or_verify_branch(repo_full_name, branch_name, source_branch='main', **kwargs):
                return 'mock-branch-sha'

logger = logging.getLogger('control-center-workloads')
project_id = PROJECT_ID

# Sweep outcomes written by sweep_expired_sandboxes_endpoint (interim lane-18 guard): shown as-is instead of being
# masked by the derived EXPIRATION_IMMINENT display status (an expired sandbox always has <= 3 days remaining).
SWEEP_OUTCOME_STATUSES = ("GUARD_REFUSED", "DECOMMISSION_FAILED")

router = APIRouter(tags=['Workloads'])

def cancel_workload_active_executions(target_product_id: str, operator_email: str, reason: str,
                                      failures: Optional[List[Dict[str, Any]]] = None) -> int:
    """
    Finds and aborts any active/running pipeline executions for target_product_id: cancels the bound Cloud Workflows
    execution (SAT-43: Workflows REST API, typed outcome) and marks the record ABORTED. Returns the number marked.
    C10: the body is shared.sandbox_sweep.cancel_active_executions (the sandbox-workload-sweeper-job runs the same code).

    Fail closed (SAT-43): when the bound execution could not be cancelled (it may still be running) the record is NOT
    marked ABORTED; the attempt is kept on it (abort_attempt) and one entry {trace_id, execution, reason, detail} is
    appended to `failures` (when given), so the caller reports it. A failure to read the run records is appended too
    (trace_id None, reason PIPELINE_EXECUTIONS_UNREADABLE).
    """
    # BUILD-ADMISSION-QUEUE: the workload's queued builds never start (never raises; the pump also refuses them).
    build_queue.cancel_product_queue(db, target_product_id, f"{operator_email}: {reason}")
    return sandbox_sweep.cancel_active_executions(
        db, target_product_id, operator_email, reason, failures, wfx.cancel_bound_execution, wfx.FAILED,
        PROJECT_ID or os.getenv("PROJECT_ID", ""))


def _cascade_failure_note(failures: List[Dict[str, Any]]) -> str:
    """One line for the decommission message / sweep errors (SAT-43)."""
    return sandbox_sweep.cascade_failure_note(failures)

# RT14-03: the attributes shown per resource. Fixed non-secret names only (never "the first few scalars", which can be
# a private key or a password); a value the engine marks sensitive is dropped even when its name is listed here.
STATE_SUMMARY_ATTRIBUTES = ("location", "region", "uri", "url", "email", "name", "project", "bucket", "topic", "status",
                            "deletion_protection", "service_account")
STATE_FALLBACK_ATTRIBUTES = ("self_link", "display_name", "account_id", "repository_id", "format", "database_version",
                             "machine_type", "zone", "role", "member")
SENSITIVE_PLACEHOLDER = "(sensitive value)"   # the terraform server's plan_redaction placeholder (same text)


class _UnreadableSensitiveMark(Exception):
    """A `sensitive_attributes` entry whose shape this reader does not know (RT14-03: fail closed)."""


def _sensitive_top_level_attributes(marks: Any) -> set:
    """Top-level attribute names the engine marks sensitive in a state instance (`sensitive_attributes`): a list of
    paths, each a list of steps `{"type": "get_attr", "value": <name>}` (or a single step). Typed marks only, never a
    name or value pattern (invariant 2). Raises _UnreadableSensitiveMark on any other shape."""
    if marks in (None, []):
        return set()
    if not isinstance(marks, list):
        raise _UnreadableSensitiveMark(type(marks).__name__)
    names = set()
    for path in marks:
        step = path[0] if isinstance(path, list) and path else path
        if not (isinstance(step, dict) and step.get("type") == "get_attr" and isinstance(step.get("value"), str)):
            raise _UnreadableSensitiveMark(repr(path)[:80])
        names.add(step["value"])
    return names
SENSITIVE_OUTPUT_PLACEHOLDER = SENSITIVE_PLACEHOLDER   # RT14-09 name for the same text


def _without_sensitive_attributes(attrs: Dict[str, Any], sensitive_paths: Any) -> Dict[str, Any]:
    """RT14-09: `attrs` without every top-level attribute that a typed `sensitive_attributes` path of the state instance
    starts at (`[{"type": "get_attr", "value": "<name>"}, ...]`). Unmarked attributes are unchanged. RT14-03: a mark
    of any other shape raises _UnreadableSensitiveMark (the caller shows no attribute of that instance)."""
    marked = _sensitive_top_level_attributes(sensitive_paths)
    return {k: v for k, v in attrs.items() if k not in marked} if marked else attrs


def _masked_record_outputs(outputs: Any) -> Any:
    """RT14-09: a `terraform_deployments` record's outputs (`output -json` shape) with every `sensitive: true` value
    masked (records written before the terraform server masked at the source)."""
    if not isinstance(outputs, dict):
        return outputs
    return {k: (dict(v, value=SENSITIVE_OUTPUT_PLACEHOLDER) if isinstance(v, dict) and v.get("sensitive") is True
                and "value" in v else v) for k, v in outputs.items()}


def parse_tfstate_json(state_json_str: str, source_label: str) -> Dict[str, Any]:
    """Parses raw terraform.tfstate JSON and extracts deployed resources and outputs.
    RT14-03: an output whose `sensitive` is true is masked, attributes the instance's `sensitive_attributes` name are
    dropped (an instance whose marks cannot be read shows no attributes), and only fixed non-secret attribute names
    are shown."""
    try:
        data = json.loads(state_json_str)
    except Exception as e:
        logger.warning(f"Failed to parse state JSON: {e}")
        return {"resources": [], "outputs": {}, "resources_count": 0}

    resources_list = []
    for res in data.get("resources", []):
        mode = res.get("mode", "managed")
        res_type = res.get("type", "")
        res_name = res.get("name", "")
        provider = res.get("provider", "")
        module = res.get("module", "root")

        for inst in res.get("instances", []):
            # RT14-09 / RT14-03: never show an attribute the engine marks sensitive (its typed `sensitive_attributes`
            # paths); an unreadable mark fails closed (no attribute of that instance is shown)
            attrs = inst.get("attributes", {}) or {}
            try:
                visible = _without_sensitive_attributes(attrs, inst.get("sensitive_attributes"))
            except _UnreadableSensitiveMark as mark_err:
                logger.warning(f"{source_label}: {res_type}.{res_name}: sensitive_attributes not readable "
                               f"({mark_err}); its attributes are not shown")
                visible = {}
            inst_id = str(visible.get("id") or visible.get("name") or visible.get("uri") or f"{res_type}.{res_name}")

            # Extract key summary attributes for tabular inspection
            summary_attrs = {}
            for k in STATE_SUMMARY_ATTRIBUTES:
                if k in visible and visible[k] is not None:
                    summary_attrs[k] = visible[k]

            if not summary_attrs:
                summary_attrs = {k: visible[k] for k in STATE_FALLBACK_ATTRIBUTES
                                 if isinstance(visible.get(k), (str, int, float, bool))}

            resources_list.append(
                DeployedResource(
                    resource_type=res_type,
                    resource_name=res_name,
                    resource_id=inst_id,
                    provider=provider,
                    module=module,
                    mode=mode,
                    attributes=summary_attrs,
                )
            )

    raw_outputs = data.get("outputs", {})
    outputs = {}
    for k, v in raw_outputs.items():
        if isinstance(v, dict) and "value" in v:
            # RT14-09: a state output the engine marks sensitive is never shown in clear text
            outputs[k] = SENSITIVE_PLACEHOLDER if v.get("sensitive") is True else v["value"]
        else:
            outputs[k] = v

    return {
        "terraform_version": data.get("terraform_version"),
        "serial": data.get("serial"),
        "state_source": source_label,
        "resources_count": len(resources_list),
        "resources": resources_list,
        "outputs": outputs,
    }


def get_platform_default_deployed_assets(project_id_val: str) -> Dict[str, Any]:
    """Synthesizes the platform core infrastructure resources provisioned in Layer 1."""
    resources = [
        DeployedResource(
            resource_type="google_artifact_registry_repository",
            resource_name="castor_docker_repo",
            resource_id=f"projects/{project_id_val}/locations/us-central1/repositories/castor-docker-repo",
            attributes={"format": "DOCKER", "repository_id": "castor-docker-repo", "location": "us-central1"},
        ),
        DeployedResource(
            resource_type="google_firestore_database",
            resource_name="castor_state_db",
            resource_id=f"(default)",
            attributes={"type": "FIRESTORE_NATIVE", "location": "us-central1", "delete_protection": "DISABLED"},
        ),
        DeployedResource(
            resource_type="google_storage_bucket",
            resource_name="workload_tfstate_bucket",
            resource_id=f"gs://castor-tfstate-{project_id_val}",
            attributes={"versioning": True, "location": "us-central1"},
        ),
        DeployedResource(
            resource_type="google_cloud_run_v2_service",
            resource_name="product-control-center-ui",
            resource_id=f"projects/{project_id_val}/locations/us-central1/services/product-control-center-ui",
            attributes={"ingress": "INGRESS_TRAFFIC_ALL", "location": "us-central1", "role": "Control Console Portal"},
        ),
        DeployedResource(
            resource_type="google_cloud_run_v2_service",
            resource_name="spec-ingestion-service",
            resource_id=f"projects/{project_id_val}/locations/us-central1/services/spec-ingestion-service",
            attributes={"ingress": "INTERNAL_ONLY", "location": "us-central1", "role": "Google Drive Spec Ingestion"},
        ),
        DeployedResource(
            resource_type="google_cloud_run_v2_service",
            resource_name="orchestrator-gateway-service",
            resource_id=f"projects/{project_id_val}/locations/us-central1/services/orchestrator-gateway-service",
            attributes={"ingress": "INTERNAL_ONLY", "location": "us-central1", "role": "Workflow Task Gateway"},
        ),
        DeployedResource(
            resource_type="google_cloud_run_v2_service",
            resource_name="mcp-terraform-server",
            resource_id=f"projects/{project_id_val}/locations/us-central1/services/mcp-terraform-server",
            attributes={"ingress": "INTERNAL_ONLY", "location": "us-central1", "role": "Terraform MCP Tool Server"},
        ),
        DeployedResource(
            resource_type="google_cloud_run_v2_service",
            resource_name="mcp-gcloud-server",
            resource_id=f"projects/{project_id_val}/locations/us-central1/services/mcp-gcloud-server",
            attributes={"ingress": "INTERNAL_ONLY", "location": "us-central1", "role": "gcloud MCP Tool Server"},
        ),
        DeployedResource(
            resource_type="google_cloud_run_v2_service",
            resource_name="mcp-github-toolserver",
            resource_id=f"projects/{project_id_val}/locations/us-central1/services/mcp-github-toolserver",
            attributes={"ingress": "INTERNAL_ONLY", "location": "us-central1", "role": "GitHub MCP Tool Server"},
        ),
        DeployedResource(
            resource_type="google_pubsub_topic",
            resource_name="spec_intake_events",
            resource_id=f"projects/{project_id_val}/topics/spec-intake-events",
            attributes={"topic": "spec-intake-events"},
        ),
        DeployedResource(
            resource_type="google_pubsub_topic",
            resource_name="autonomous_refactor_events",
            resource_id=f"projects/{project_id_val}/topics/autonomous-refactor-events",
            attributes={"topic": "autonomous-refactor-events"},
        ),
        DeployedResource(
            resource_type="google_pubsub_topic",
            resource_name="runtime_incident_events",
            resource_id=f"projects/{project_id_val}/topics/runtime-incident-events",
            attributes={"topic": "runtime-incident-events"},
        ),
        DeployedResource(
            resource_type="google_service_account",
            resource_name="agents_architect",
            resource_id=f"sa-castor-architect@{project_id_val}.iam.gserviceaccount.com",
            attributes={"display_name": "StackVend Architect Agent", "email": f"sa-castor-architect@{project_id_val}.iam.gserviceaccount.com"},
        ),
        DeployedResource(
            resource_type="google_service_account",
            resource_name="agents_gcp_devops",
            resource_id=f"sa-castor-gcp-devops@{project_id_val}.iam.gserviceaccount.com",
            attributes={"display_name": "StackVend GCP DevOps Agent", "email": f"sa-castor-gcp-devops@{project_id_val}.iam.gserviceaccount.com"},
        ),
    ]
    return {
        "terraform_version": "1.5.7",
        "serial": 1,
        "state_source": f"gs://castor-tfstate-{project_id_val}/platform/default.tfstate",
        "resources_count": len(resources),
        "resources": resources,
        "outputs": {
            "artifact_registry_docker_repo": f"us-central1-docker.pkg.dev/{project_id_val}/castor-docker-repo",
            "firestore_database_name": "(default)",
            "workload_tfstate_bucket_name": f"castor-tfstate-{project_id_val}",
        },
    }


OUTPUTS_MANAGER_ONLY = "OUTPUTS_MANAGER_ONLY"
_OUTPUT_READER_ROLES = frozenset({UserRole.ADMIN, UserRole.WORKLOAD_MANAGER, UserRole.APPROVER})


def _may_read_outputs(request: Request) -> bool:
    """RT14-03: workload managers (legacy APPROVER included) and administrators read OpenTofu outputs. A VIEWER, or a
    role this check cannot read, does not (fails closed)."""
    role = getattr(getattr(request, "state", None), "user_role", None)
    if isinstance(role, str) and not isinstance(role, UserRole):
        try:
            role = UserRole(role)
        except ValueError:
            return False
    return role in _OUTPUT_READER_ROLES


def _is_workload_state_object(name: Any, product_id: str) -> bool:
    """RT14-03: True only for `workloads/<product_id>/<file>.tfstate` (exactly three segments, exact id)."""
    if not isinstance(name, str):
        return False
    parts = name.split("/")
    return (len(parts) == 3 and parts[0] == "workloads" and parts[1] == product_id
            and parts[2].endswith(".tfstate") and parts[2] != ".tfstate")


def fetch_workload_state_from_gcs(product_id: str, project_id_val: str) -> Optional[Dict[str, Any]]:
    """Attempts to download and parse the Terraform state file from GCS."""
    if not storage:
        return None

    state_bucket_name = os.getenv("TFSTATE_BUCKET", "") or (f"castor-tfstate-{project_id_val}" if project_id_val else "")
    if not state_bucket_name:
        return None
    if product_id not in ["project-castor", "castor", "platform"]:
        # FD-7L Phase 3 (plan 2.9): Shared install -> the same bucket, nothing read; Per workload -> the bucket named
        # by vending's signed provenance record (the platform bucket only while that record is not READY).
        from services import runner_state
        try:
            state_bucket_name = runner_state.state_bucket(product_id, state_bucket_name)
        except runner_state.ri.RunnerIdentityError as loc_err:
            logger.error(f"State location of {product_id} unknown ({loc_err.code}): {loc_err.detail}")
            return None

    try:
        storage_client = storage.Client(project=project_id_val or project_id)
        bucket = storage_client.bucket(state_bucket_name)

        prefixes_to_try = [
            f"workloads/{product_id}/default.tfstate",
            f"workloads/{product_id}/terraform.tfstate",
            f"workloads/{product_id}.tfstate",
        ]
        if product_id in ["project-castor", "castor", "platform"]:
            prefixes_to_try.extend([
                "platform/default.tfstate",
                "platform/terraform.tfstate",
                "default.tfstate",
                "terraform.tfstate",
            ])

        for blob_path in prefixes_to_try:
            blob = bucket.blob(blob_path)
            if blob.exists():
                content = blob.download_as_text()
                if isinstance(content, str) and content.strip().startswith("{"):
                    logger.info(f"Found tfstate for {product_id} in gs://{state_bucket_name}/{blob_path}")
                    res = parse_tfstate_json(content, f"gs://{state_bucket_name}/{blob_path}")
                    if res.get("resources_count", 0) > 0:
                        return res

        # List the state files directly in this workload's own folder. RT14-03: the prefix ends with "/" and every
        # name is checked segment by segment, so `workloads/app-billing/...` is never read for `app`, and the
        # decommission archives under `workloads/<id>/state_history/` are never shown as the current state.
        prefix = f"workloads/{product_id}/"
        blobs = list(bucket.list_blobs(prefix=prefix, max_results=10))
        for b in blobs:
            if _is_workload_state_object(b.name, product_id):
                content = b.download_as_text()
                if isinstance(content, str) and content.strip().startswith("{"):
                    logger.info(f"Found tfstate for {product_id} at gs://{state_bucket_name}/{b.name}")
                    res = parse_tfstate_json(content, f"gs://{state_bucket_name}/{b.name}")
                    if res.get("resources_count", 0) > 0:
                        return res

    except Exception as e:
        logger.warning(f"Could not read tfstate from GCS ({e}) for {product_id}")

    return None


@router.get("/api/workloads", response_model=List[WorkloadSummary], dependencies=[require(SCOPED)])
def list_workloads(request: Request):
    """Returns list of active managed workloads from Firestore, scoped to user authorization."""
    user_role = getattr(request.state, "user_role", UserRole.VIEWER)
    assigned = getattr(request.state, "assigned_workloads", [])
    # FD-4N: platform pseudo-workloads are ADMIN-only (red-team H8); never read TEST_MODE.
    clean_assigned = [p.strip().lower() for p in (assigned or []) if isinstance(p, str) and p.strip()
                      and p.strip().lower() not in PLATFORM_PSEUDO_WORKLOADS]

    if db:
        try:
            results = []
            if user_role == UserRole.ADMIN:
                docs = db.collection("workloads").stream()
                for d in docs:
                    data = d.to_dict() or {}
                    current_spend = float(data.get("current_spend_usd", 0.0))
                    budget_ceiling = float(data.get("budget_ceiling_monthly_usd", 40.0))
                    proj_spend = float(data.get("projected_monthly_spend_usd", calculate_run_rate_projection(current_spend)))
                    is_overrun = bool(data.get("is_overrun_projected", proj_spend > budget_ceiling))

                    results.append(
                        WorkloadSummary(
                            product_id=data.get("product_id", d.id),
                            project_id=data.get("project_id", d.id),
                            vcs_provider=data.get("vcs_provider", "GITHUB"),
                            github_repo=_stored_repo_name(data.get("github_repo")),
                            default_branch=data.get("default_branch", "main"),
                            folder_id=data.get("folder_id") or data.get("parent_folder_id"),
                            folder_name=data.get("folder_name"),
                            status=data.get("status", "ACTIVE"),
                            budget_ceiling_monthly_usd=budget_ceiling,
                            current_spend_usd=current_spend,
                            projected_monthly_spend_usd=proj_spend,
                            spend_last_updated_at=data.get("spend_last_updated_at"),
                            is_overrun_projected=is_overrun,
                            spend_source=data.get("spend_source"),
                            cached_hourly_burn_usd=data.get("cached_hourly_burn_usd"),
                            service_url=data.get("service_url"),
                            service_url_unknown_reason=data.get("service_url_unknown_reason"),
                            created_at=data.get("created_at"),
                            is_castor=bool(data.get("is_castor", d.id in ["project-castor", "castor", "platform"])),
                            code_freeze=bool(data.get("code_freeze", False)),
                            sre_auto_healing_enabled=bool(data.get("sre_auto_healing_enabled", True)),
                            refactor_scanner_enabled=bool(data.get("refactor_scanner_enabled", True)),
                            require_human_code_review=bool(data.get("require_human_code_review", True)) if data.get("auto_merge") is None else not bool(data.get("auto_merge")),
                            auto_merge=bool(data.get("auto_merge", False)) if data.get("require_human_code_review") is None else not bool(data.get("require_human_code_review")),
                            require_plan_approval=bool(data.get("require_plan_approval", False)),
                            budget_breach_policy=data.get("budget_breach_policy", "AUTONOMOUS_SCALE_TO_ZERO"),
                            buffer_ceiling_usd=data.get("buffer_ceiling_usd"),
                            iac_engine=data.get("iac_engine", "TERRAFORM"),
                            region=_recorded_region(data),   # SAT-44: the catalog card shows it
                            decommissioned_at=data.get("decommissioned_at"),
                            decommissioned_by=data.get("decommissioned_by"),
                            archived_at=data.get("archived_at"),
                            archived_by=data.get("archived_by"),
                            last_active_project_id=data.get("last_active_project_id"),
                            last_iac_upgrade_at=data.get("last_iac_upgrade_at"),
                            last_iac_upgrade_by=data.get("last_iac_upgrade_by"),
                            last_iac_upgrade_status=data.get("last_iac_upgrade_status"),
                            iac_drift_detected=data.get("iac_drift_detected"),
                            iac_drift_count=data.get("iac_drift_count", 0),
                            is_sandbox=bool(data.get("is_sandbox", False)),
                            sandbox_ttl_days=data.get("sandbox_ttl_days", 30),
                            sandbox_expires_at=data.get("sandbox_expires_at"),
                            sandbox_days_remaining=compute_days_remaining(data.get("sandbox_expires_at")) if data.get("is_sandbox") else None,
                            sandbox_auto_decommission=bool(data.get("sandbox_auto_decommission", data.get("is_sandbox", False))),
                            **destructive_actions.sandbox_display_fields(data),
                            sandbox_decommission_status="EXPIRATION_IMMINENT" if (data.get("is_sandbox") and compute_days_remaining(data.get("sandbox_expires_at")) is not None and compute_days_remaining(data.get("sandbox_expires_at")) <= 3.0 and data.get("status") != "DECOMMISSIONED" and data.get("sandbox_decommission_status") not in SWEEP_OUTCOME_STATUSES) else data.get("sandbox_decommission_status"),
                            cumulative_lifespan_days=int(data.get("cumulative_lifespan_days", data.get("sandbox_ttl_days", 30) if data.get("is_sandbox") else 0)),
                            extension_count=int(data.get("extension_count", 0)),
                            max_extensions_allowed=3,
                            max_cumulative_days_allowed=90,
                            creator_email=data.get("creator_email") or data.get("initialized_by"),
                            **compliance_label(data),   # COMPLIANCE-BASELINE-LABEL (display only)
                        )
                    )
                return results
            else:
                if not clean_assigned:
                    return []
                doc_refs = [db.collection("workloads").document(pid) for pid in clean_assigned]
                snapshots = db.get_all(doc_refs)
                for snap in snapshots:
                    if snap.exists:
                        data = snap.to_dict() or {}
                        current_spend = float(data.get("current_spend_usd", 0.0))
                        budget_ceiling = float(data.get("budget_ceiling_monthly_usd", 40.0))
                        proj_spend = float(data.get("projected_monthly_spend_usd", calculate_run_rate_projection(current_spend)))
                        is_overrun = bool(data.get("is_overrun_projected", proj_spend > budget_ceiling))

                        results.append(
                            WorkloadSummary(
                                product_id=data.get("product_id", snap.id),
                                project_id=data.get("project_id", snap.id),
                                vcs_provider=data.get("vcs_provider", "GITHUB"),
                                github_repo=_stored_repo_name(data.get("github_repo")),
                                default_branch=data.get("default_branch", "main"),
                                folder_id=data.get("folder_id") or data.get("parent_folder_id"),
                                folder_name=data.get("folder_name"),
                                status=data.get("status", "ACTIVE"),
                                budget_ceiling_monthly_usd=budget_ceiling,
                                current_spend_usd=current_spend,
                                projected_monthly_spend_usd=proj_spend,
                                spend_last_updated_at=data.get("spend_last_updated_at"),
                                is_overrun_projected=is_overrun,
                                spend_source=data.get("spend_source"),
                                cached_hourly_burn_usd=data.get("cached_hourly_burn_usd"),
                                service_url=data.get("service_url"),
                                service_url_unknown_reason=data.get("service_url_unknown_reason"),
                                created_at=data.get("created_at"),
                                is_castor=bool(data.get("is_castor", snap.id in ["project-castor", "castor", "platform"])),
                                code_freeze=bool(data.get("code_freeze", False)),
                                sre_auto_healing_enabled=bool(data.get("sre_auto_healing_enabled", True)),
                                refactor_scanner_enabled=bool(data.get("refactor_scanner_enabled", True)),
                                require_human_code_review=bool(data.get("require_human_code_review", True)) if data.get("auto_merge") is None else not bool(data.get("auto_merge")),
                                auto_merge=bool(data.get("auto_merge", False)) if data.get("require_human_code_review") is None else not bool(data.get("require_human_code_review")),
                                require_plan_approval=bool(data.get("require_plan_approval", False)),
                                iac_engine=data.get("iac_engine", "TERRAFORM"),
                                region=_recorded_region(data),   # SAT-44: the catalog card shows it
                                decommissioned_at=data.get("decommissioned_at"),
                                decommissioned_by=data.get("decommissioned_by"),
                                archived_at=data.get("archived_at"),
                                archived_by=data.get("archived_by"),
                                last_active_project_id=data.get("last_active_project_id"),
                                last_iac_upgrade_at=data.get("last_iac_upgrade_at"),
                                last_iac_upgrade_by=data.get("last_iac_upgrade_by"),
                                last_iac_upgrade_status=data.get("last_iac_upgrade_status"),
                                iac_drift_detected=data.get("iac_drift_detected"),
                                iac_drift_count=data.get("iac_drift_count", 0),
                                is_sandbox=bool(data.get("is_sandbox", False)),
                                sandbox_ttl_days=data.get("sandbox_ttl_days", 30),
                                sandbox_expires_at=data.get("sandbox_expires_at"),
                                sandbox_days_remaining=compute_days_remaining(data.get("sandbox_expires_at")) if data.get("is_sandbox") else None,
                                sandbox_auto_decommission=bool(data.get("sandbox_auto_decommission", data.get("is_sandbox", False))),
                                **destructive_actions.sandbox_display_fields(data),
                                sandbox_decommission_status="EXPIRATION_IMMINENT" if (data.get("is_sandbox") and compute_days_remaining(data.get("sandbox_expires_at")) is not None and compute_days_remaining(data.get("sandbox_expires_at")) <= 3.0 and data.get("status") != "DECOMMISSIONED" and data.get("sandbox_decommission_status") not in SWEEP_OUTCOME_STATUSES) else data.get("sandbox_decommission_status"),
                                cumulative_lifespan_days=int(data.get("cumulative_lifespan_days", data.get("sandbox_ttl_days", 30) if data.get("is_sandbox") else 0)),
                                extension_count=int(data.get("extension_count", 0)),
                                max_extensions_allowed=3,
                                max_cumulative_days_allowed=90,
                                creator_email=data.get("creator_email") or data.get("initialized_by"),
                                **compliance_label(data),   # COMPLIANCE-BASELINE-LABEL (display only)
                            )
                        )
                return results
        except Exception as e:
            logger.warning(f"Failed to query workloads from Firestore ({e}). Returning empty list.")

    return []


def extract_text_from_file_bytes(filename: str, content: bytes) -> Tuple[str, str, Optional[int]]:
    """
    Extracts plain text and page counts from uploaded files:
    Supports .pdf, .docx, .md, .txt, .json, .yaml, .yml.
    Returns: (extracted_text, file_type, pages_count)
    """
    ext = os.path.splitext(filename)[1].lower()

    if ext == ".pdf":
        try:
            import pypdf
            reader = pypdf.PdfReader(io.BytesIO(content))
            pages_count = len(reader.pages)
            extracted_pages = []
            for i, page in enumerate(reader.pages):
                page_text = page.extract_text() or ""
                if page_text.strip():
                    extracted_pages.append(f"<!-- Page {i+1} -->\n{page_text.strip()}")
            full_text = "\n\n".join(extracted_pages)
            return full_text, "PDF", pages_count
        except Exception as e:
            logger.error(f"PDF extraction error for '{filename}': {e}")
            raise HTTPException(status_code=400, detail=f"Failed to extract text from PDF: {str(e)}")

    elif ext == ".docx":
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                if "word/document.xml" not in z.namelist():
                    raise ValueError("Not a valid DOCX file: missing word/document.xml")
                xml_content = z.read("word/document.xml")
                tree = ET.fromstring(xml_content)
                paragraphs = []
                for p in tree.iter():
                    if p.tag.endswith("}p"):
                        p_texts = [node.text for node in p.iter() if node.text and node.tag.endswith("}t")]
                        if p_texts:
                            paragraphs.append("".join(p_texts))
                full_text = "\n\n".join(paragraphs)
                words = len(full_text.split())
                est_pages = max(1, (words + 399) // 400)
                return full_text, "DOCX", est_pages
        except Exception as e:
            logger.error(f"DOCX extraction error for '{filename}': {e}")
            raise HTTPException(status_code=400, detail=f"Failed to extract text from Word document: {str(e)}")

    elif ext in [".md", ".txt", ".json", ".yaml", ".yml"]:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = content.decode("latin-1")
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Failed to decode text file: {str(e)}")
        file_type = "MARKDOWN" if ext == ".md" else ("TEXT" if ext == ".txt" else ext[1:].upper())
        words = len(text.split())
        est_pages = max(1, (words + 399) // 400)
        return text, file_type, est_pages

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext}'. Supported formats: .pdf, .docx, .md, .txt, .json, .yaml, .yml",
        )


def derive_slug_and_title_from_text(filename: str, text: str) -> Tuple[str, str]:
    """Derives a clean product slug and title from the filename or document header."""
    base_name = os.path.splitext(filename)[0]
    clean_slug = re.sub(r"[^a-zA-Z0-9]+", "-", base_name).strip("-").lower()
    clean_slug = re.sub(r"^(spec|doc|document|architecture|plan|castor)-+", "", clean_slug)
    if not clean_slug:
        clean_slug = "custom-workload"
    clean_slug = clean_slug[:40].rstrip("-")

    lines = [line.strip() for line in text.splitlines()[:20] if line.strip()]
    detected_title = ""
    for line in lines:
        if line.startswith("# "):
            detected_title = line.lstrip("# ").strip()
            break
        elif line.lower().startswith("title:"):
            detected_title = line.split(":", 1)[1].strip().strip('"\'')
            break
    if not detected_title:
        words = re.sub(r"[-_]+", " ", base_name).split()
        detected_title = " ".join(w.capitalize() for w in words[:6])

    return clean_slug, detected_title


@router.post("/api/workloads/extract-document-text", response_model=ExtractedDocumentResponse, dependencies=[require(ADMIN)])
async def extract_document_text_endpoint(
    request: Request,
    file: UploadFile = File(...),
):
    """
    Extracts full text and metadata from uploaded specification documents (PDF, DOCX, Markdown, Text).
    Supports large multi-page specifications (90+ pages).
    """
    verify_admin_access(request)

    filename = file.filename or "uploaded-document.txt"
    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read uploaded file: {str(e)}")

    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    if len(content) > 25 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Uploaded document exceeds the 25 MB size limit.")

    extracted_text, file_type, pages_count = extract_text_from_file_bytes(filename, content)

    words = len(extracted_text.split())
    chars = len(extracted_text)
    suggested_slug, suggested_title = derive_slug_and_title_from_text(filename, extracted_text)

    return ExtractedDocumentResponse(
        filename=filename,
        file_type=file_type,
        character_count=chars,
        word_count=words,
        pages_count=pages_count,
        suggested_slug=suggested_slug,
        suggested_title=suggested_title,
        text=extracted_text,
    )


def _gha_deploy_switch(data: Any, vcs_provider: Any) -> Optional[bool]:
    """GHA-DEPLOY-SWITCH: the workload document's switch (missing = on); always on for Serverless Git (the switch
    is GitHub-only). None when the stored value is not true / false (or the reader is unavailable)."""
    if str(vcs_provider or "").strip().upper() == "SERVERLESS_GIT":
        return True
    value = data.get(GITHUB_ACTIONS_DEPLOY_FIELD) if isinstance(data, dict) else None
    if value is None:
        return True
    if github_actions_deploy_enabled is None:
        return None
    try:
        return github_actions_deploy_enabled(value)
    except ValueError:
        return None


def _express_gha_deploy(product_id: str, vcs_provider: str) -> Tuple[bool, Optional[tuple]]:
    """GHA-DEPLOY-SWITCH: (switch, failure) for the Express synthesizer from workloads/{pid}.github_actions_deploy.
    Serverless Git -> on, nothing read. An unreadable document or an invalid value -> a typed (error_class, detail)
    failure (never guessed: off removes the WIF resources, on keeps a deploy path the administrator turned off)."""
    if str(vcs_provider or "").strip().upper() == "SERVERLESS_GIT":
        return True, None
    if not db:
        return True, ("GHA_DEPLOY_SWITCH_UNAVAILABLE", "no Firestore: the GitHub Actions deploy switch cannot be read")
    try:
        snap = db.collection("workloads").document(product_id).get()
    except Exception as e:  # noqa: BLE001
        return True, ("GHA_DEPLOY_SWITCH_UNAVAILABLE", f"workloads/{product_id} unreadable ({type(e).__name__})")
    data = snap.to_dict() if getattr(snap, "exists", False) else {}
    switch = _gha_deploy_switch(data, vcs_provider)
    if switch is None:
        return True, ("GHA_DEPLOY_SWITCH_INVALID", f"workloads/{product_id}.{GITHUB_ACTIONS_DEPLOY_FIELD} is not true "
                                                    "or false; an administrator sets it on the workload page.")
    return switch, None


def _express_runner_mode() -> Tuple[Optional[str], Optional[tuple]]:
    """FD-7L-F4: (operative runner identity mode, failure) for the Express synthesizer (it decides whether Express
    commits backend.tf), through the one shared reader. A mode that cannot be read -> the reader's typed class."""
    from services import runner_state   # lazy, as the resources view
    try:
        return runner_state.operative_mode(), None
    except runner_state.ri.RunnerIdentityError as e:
        return None, (e.code, e.detail)


def _express_access_policy(product_id: str) -> Tuple[Optional[Any], Optional[tuple]]:
    """FD-4CS: (policy, failure) for the Express synthesizer from the stored ``workloads/{pid}.access`` record, the
    workload's only access record. A workload document without one (an Express workload created before FD-4CS) ->
    (None, None): its services keep their previous rendering. No Firestore, no workload document, an unreadable
    document or an invalid record -> a typed (error_class, detail) failure: never rendered public because the record
    could not be read or used (Fable RT 10-24: fail closed)."""
    if not db:
        return None, ("ACCESS_POLICY_UNAVAILABLE", "no Firestore: the access record cannot be read")
    try:
        snap = db.collection("workloads").document(product_id).get()
    except Exception as e:  # noqa: BLE001
        return None, ("ACCESS_POLICY_UNAVAILABLE", f"workloads/{product_id} unreadable ({type(e).__name__})")
    if not getattr(snap, "exists", False):
        return None, ("ACCESS_POLICY_UNAVAILABLE", f"workloads/{product_id} does not exist: the access record cannot "
                                                   "be read")
    data = snap.to_dict()
    record = data.get("access") if isinstance(data, dict) else None
    if record is None:
        return None, None
    policy = stored_access_policy(record)
    if policy is None:
        return None, ("ACCESS_POLICY_INVALID", f"workloads/{product_id}.access is not a valid access record; an "
                                               f"administrator sets it (PATCH /api/workloads/{product_id}/access).")
    return policy, None


def execute_express_provisioning(
    product_id: str,
    target_project_id: str,
    clean_vcs_provider: str,
    full_github_repo: str,
    target_branch: str,
    target_folder: Optional[str],
    budget: float,
    clean_engine: str,
    is_sandbox: bool,
    admin_email: str,
    module_instances: List[Any],
    include_vpc: bool,
    trace_id: str,
    vending_url: Optional[str] = None,
    terraform_url: Optional[str] = None,
    sandbox_auto_decommission: bool = False,
    sandbox_designation_source: Optional[str] = None,
    sandbox_ttl_days: Optional[int] = None,
    approved_removals: Optional[List[str]] = None,
    region: Optional[str] = None,
):
    """
    `region` (FD-7M-a): the workload's region as the create route resolved and recorded it; None = the record's
    region through the settings helper (no record region: the default region). Resolved before vending: a region that
    cannot be established stops the run typed (REGION_NOT_APPROVED / REGION_UNAVAILABLE), nothing is vended.

    `approved_removals` (EXP-7): the resource addresses the operator approved for deletion/replacement; every Express
    deploy sends `refuse_destroy: true`, so the terraform service refuses any other delete/replace of a resource in
    state with a typed 409 DESTROY_REQUIRES_APPROVAL (the workload is then FAILED with that reason).

    Executes the deterministic Express provisioning pipeline:
    1. Records execution stages in Firestore pipeline_executions
    2. Vends GCP child project and Git repository
    3. Synthesizes multi-instance OpenTofu HCL and module files
    4. Commits initial IaC to the repository
    5. Dispatches apply to mcp-terraform-server
    6. Updates pipeline and workload status to ACTIVE on an HTTP 200 from /deploy; any other outcome (EXP-8: no
       terraform service, a raised call or timeout, any non-200) makes the terraform stage, the pipeline and the
       workload FAILED with a typed reason (the response's `detail.error_class`, else EXPRESS_DEPLOY_FAILED; a
       timed-out call is EXPRESS_DEPLOY_OUTCOME_UNKNOWN because the apply may still finish)
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    logger.info(f"Starting Express workload provisioning for '{product_id}' (Trace: {trace_id})")

    # 1. Pipeline Execution doc
    if db:
        try:
            initial_exec = {
                "trace_id": trace_id,
                "product_id": product_id,
                "project_id": target_project_id,
                "vcs_provider": clean_vcs_provider,
                "github_repo": full_github_repo,
                "status": "IN_PROGRESS",
                "current_stage": "VENDING",
                "creation_mode": "EXPRESS",
                "created_at": now_iso,
                "stages": {
                    "vending": {"status": "IN_FLIGHT", "started_at": now_iso, "summary": "Vending GCP project and Git repository"},
                    "hcl_synthesis": {"status": "QUEUED"},
                    "vcs_seed": {"status": "QUEUED"},
                    "terraform": {"status": "QUEUED"},
                },
                "outputs": {
                    "github_repo": full_github_repo,
                    "product_id": product_id,
                },
            }
            db.collection("pipeline_executions").document(trace_id).set(initial_exec)
        except Exception as pe_err:
            logger.warning(f"Could not persist initial express pipeline execution {trace_id}: {pe_err}")

    # FD-7M-a (F-D): the workload's own region, before anything is vended (never the host $REGION or a literal).
    express_region, region_failure = _express_workload_region(product_id, region)
    if region_failure is not None:
        _record_express_region_failure(product_id, trace_id, *region_failure)
        return

    # 2. Vending
    vended_pid = target_project_id
    vended_repo = full_github_repo
    vending_failure: Optional[Dict[str, Any]] = None
    try:
        v_resp = make_vending_request(
            method="POST",
            path="/vend-all",
            json_body={
                "product_id": product_id,
                "trace_id": trace_id,
                "initial_budget": budget,
                "folder_id": target_folder,
                "vcs_provider": clean_vcs_provider,
                # Lane 18 S2: the explicit sandbox designation vending records at birth (TTL eligibility).
                **destructive_actions.vend_sandbox_fields(
                    is_sandbox=is_sandbox, auto_decommission=sandbox_auto_decommission,
                    designation_source=sandbox_designation_source, ttl_days=sandbox_ttl_days),
            },
            timeout=120.0,
        )
        if v_resp and getattr(v_resp, "status_code", 0) == 200:
            v_data = v_resp.json()
            if v_data.get("project_id"):
                vended_pid = v_data["project_id"]
            if _stored_repo_name(v_data.get("github_repo")):
                vended_repo = _stored_repo_name(v_data.get("github_repo"))
            logger.info(f"Vended express project '{vended_pid}' and repository '{vended_repo}'")
        else:
            vending_failure = _express_vending_failure(v_resp)
    except Exception as v_err:
        logger.warning(f"Express vending service call notice: {v_err}")

    if vending_failure is not None:
        # FD-4AI (owner 10-26, D9): vending answered with a typed failure (e.g. BILLING_NOT_LINKED): the vending
        # stage, the pipeline and the workload are FAILED with that class and nothing is synthesized or deployed.
        _record_express_vending_failure(product_id, trace_id, vending_failure)
        return

    if db:
        try:
            db.collection("pipeline_executions").document(trace_id).set({
                "current_stage": "HCL_SYNTHESIS",
                "project_id": vended_pid,
                "github_repo": vended_repo,
                "stages": {
                    "vending": {"status": "SUCCESS", "completed_at": datetime.now(timezone.utc).isoformat(), "summary": f"Vended project {vended_pid}"},
                    "hcl_synthesis": {"status": "IN_FLIGHT", "started_at": datetime.now(timezone.utc).isoformat(), "summary": "Synthesizing multi-instance OpenTofu HCL and module files"},
                }
            }, merge=True)
            db.collection("workloads").document(product_id).set({
                "project_id": vended_pid,
                "github_repo": vended_repo,
            }, merge=True)
        except Exception as db_err:
            logger.warning(f"Error updating express status: {db_err}")

    # 3. HCL Synthesis
    synthesizer = ExpressHCLSynthesizer(db=db) if ExpressHCLSynthesizer else None
    state_bucket_name = os.getenv("TFSTATE_BUCKET", "") or (f"castor-tfstate-{vended_pid}")
    hcl_files = {}
    subnet_cidr = None
    if synthesizer and synthesizer.requires_private_network(module_instances):
        # FD-CSQL: the private-IP database's VPC subnet comes from the platform IPAM (fail closed on any error:
        # var.subnet_cidr is then left without a value and plan stops on it).
        try:
            orch = get_platform_settings(strict=True).orchestration   # FD-4AK: the pool is never a default
            subnet_cidr = synthesizer.allocate_subnet_cidr(
                product_id, vended_pid, express_region,
                supernet_cidr=str(orch.ipam_supernet_cidr), prefix_len=int(orch.ipam_subnet_prefix),
            )
        except Exception as ipam_err:
            logger.error(f"IPAM settings unavailable for Express workload '{product_id}': {ipam_err}")
    # Express route fail-closed (EXP-5): a refused or failed synthesis is a FAILED hcl_synthesis stage with a typed
    # reason, and nothing is committed or deployed. (error_class, detail); None = synthesis produced files.
    synth_failure: Optional[tuple] = None
    access_policy, access_failure = _express_access_policy(product_id)   # FD-4CS
    gha_deploy, gha_failure = _express_gha_deploy(product_id, clean_vcs_provider)   # GHA-DEPLOY-SWITCH
    runner_mode, runner_mode_failure = _express_runner_mode()   # FD-7L-F4
    if not synthesizer:
        synth_failure = ("EXPRESS_SYNTHESIZER_UNAVAILABLE", "The Express synthesizer is not available in this service.")
    elif access_failure:
        synth_failure = access_failure
    elif gha_failure:
        synth_failure = gha_failure
    elif runner_mode_failure:
        synth_failure = runner_mode_failure
    else:
        try:
            hcl_files = synthesizer.synthesize_workload(
                product_id=product_id,
                project_id=vended_pid,
                region=express_region,
                github_repo_full_name=vended_repo,
                module_instances=module_instances,
                state_bucket=state_bucket_name,
                include_vpc=include_vpc,
                vcs_provider=clean_vcs_provider,
                iac_engine=clean_engine,
                subnet_cidr=subnet_cidr,
                access=access_policy,
                runner_identity_mode=runner_mode,   # FD-7L-F4: the operative mode (PLATFORM = the previous rendering)
                # GHA-DEPLOY-SWITCH: on = the previous rendering, byte for byte (only passed when off)
                **({} if gha_deploy else {"github_actions_deploy": False}),
            )
            logger.info(f"Synthesized {len(hcl_files)} files for express workload '{product_id}'")
        except ExpressSynthesisRefused as refused:
            synth_failure = (refused.reason, str(refused))
        except Exception as synth_err:
            synth_failure = ("EXPRESS_SYNTHESIS_ERROR", f"{type(synth_err).__name__}: {synth_err}")
        else:
            if not hcl_files:
                synth_failure = ("EXPRESS_SYNTHESIS_EMPTY", "Synthesis produced no infrastructure files.")

    if synth_failure:
        error_class, detail = synth_failure
        logger.error(f"HCL synthesis failed for express workload {product_id} ({error_class}): {detail}")
        if db:
            try:
                failed_at = datetime.now(timezone.utc).isoformat()
                skipped = {"status": "SKIPPED", "summary": "Skipped: HCL synthesis failed"}
                db.collection("pipeline_executions").document(trace_id).set({
                    "status": "FAILED",
                    "current_stage": "FAILED",
                    "error_class": error_class,
                    "error_message": detail,
                    "completed_at": failed_at,
                    "ended_at": failed_at,
                    "stages": {
                        "hcl_synthesis": {"status": "FAILED", "completed_at": failed_at, "error_class": error_class,
                                          "summary": detail},
                        "vcs_seed": dict(skipped),
                        "terraform": dict(skipped),
                    },
                }, merge=True)
                db.collection("workloads").document(product_id).set({
                    "status": "FAILED",
                    "failure_reason": f"{error_class}: {detail}",
                }, merge=True)
            except Exception as db_err:
                logger.error(f"Error recording failed express synthesis for {trace_id}: {db_err}")
        return

    if db:
        try:
            db.collection("pipeline_executions").document(trace_id).set({
                "current_stage": "VCS_SEED",
                "stages": {
                    "hcl_synthesis": {"status": "SUCCESS", "completed_at": datetime.now(timezone.utc).isoformat(), "summary": f"Synthesized {len(hcl_files)} infrastructure files"},
                    "vcs_seed": {"status": "IN_FLIGHT", "started_at": datetime.now(timezone.utc).isoformat(), "summary": f"Committing infrastructure files to {target_branch}"},
                }
            }, merge=True)
        except Exception as db_err:
            logger.warning(f"Error updating express status: {db_err}")

    # 4. VCS Seed
    committed = False
    if VCSProviderFactory is not None and hcl_files:
        try:
            provider = VCSProviderFactory.get_provider(clean_vcs_provider, product_id=product_id)
            commit_sha = provider.commit_files(
                repo_identifier=vended_repo,
                branch=target_branch,
                files=hcl_files,
                commit_message=f"feat({product_id}): Initial Express Golden Module Infrastructure",
            )
            committed = True
            logger.info(f"Committed {len(hcl_files)} files to {vended_repo} ({target_branch}) at commit {commit_sha}")
        except Exception as vcs_err:
            logger.warning(f"Could not commit files to VCS repository: {vcs_err}")

    if db:
        try:
            db.collection("pipeline_executions").document(trace_id).set({
                "current_stage": "TERRAFORM",
                "stages": {
                    "vcs_seed": {"status": "SUCCESS", "completed_at": datetime.now(timezone.utc).isoformat(), "summary": "Committed files to repository"},
                    "terraform": {"status": "IN_FLIGHT", "started_at": datetime.now(timezone.utc).isoformat(), "summary": "Applying OpenTofu infrastructure with brownfield pre-import"},
                }
            }, merge=True)
        except Exception as db_err:
            logger.warning(f"Error updating express status: {db_err}")

    # EXP-7 RT B2: an operator approval of removals is recorded on the workload (who, when, which addresses)
    if approved_removals and db:
        try:
            db.collection("workloads").document(product_id).set({
                "destroy_approval": {"approved_removals": sorted(approved_removals), "approved_by": admin_email,
                                     "approved_at": datetime.now(timezone.utc).isoformat(), "trace_id": trace_id},
            }, merge=True)
        except Exception as db_err:
            logger.error(f"Error recording the destroy approval for {trace_id}: {db_err}")

    # 5. OpenTofu / Terraform Apply. EXP-8: only an HTTP 200 from /deploy is a success; every other outcome (no
    # terraform service, a raised call/timeout, any non-200) is a FAILED terraform stage with a typed reason.
    # The client waits EXPRESS_DEPLOY_TIMEOUT_SECONDS (the terraform service's own request limit).
    service_url = ""
    try:
        tf_resp = make_terraform_request(
            method="POST",
            path="/deploy",
            json_body={
                "product_id": product_id,
                "trace_id": trace_id,
                "hcl_files": hcl_files,
                "target_project_id": vended_pid,
                "branch": target_branch,
                "iac_engine": clean_engine,
                # EXP-7: typed trigger (never inferred from the HCL); Agent-mode deploys never send it
                "refuse_destroy": True,
                "approved_removals": list(approved_removals or []),
            },
            timeout=EXPRESS_DEPLOY_TIMEOUT_SECONDS,
        )
    except Exception as tf_err:
        logger.error(f"Terraform /deploy call failed for express workload {product_id}: {type(tf_err).__name__}")
        _record_express_deploy_failure(product_id, trace_id, _express_deploy_failure(None, transport_error=tf_err))
        return
    if tf_resp is None or getattr(tf_resp, "status_code", None) != 200:
        refusal = _destroy_approval_refusal(tf_resp) if tf_resp is not None and tf_resp.status_code == 409 else None
        if refusal is not None:
            _record_express_destroy_refusal(product_id, trace_id, refusal)
        else:
            _record_express_deploy_failure(product_id, trace_id, _express_deploy_failure(tf_resp))
        return
    try:
        tf_data = tf_resp.json()
    except Exception:
        tf_data = None   # the apply succeeded (HTTP 200); only the service URL is unknown
    if isinstance(tf_data, dict):
        service_url = _express_service_url(tf_data, module_instances)
    logger.info(f"OpenTofu deployment succeeded for '{product_id}'. URL: {service_url}")

    # EXP-6 (RT F1/F2): the create write already ADDED this request's event-worker names to the stored names; after
    # a successful /deploy they are narrowed to exactly the deployed names (removed workers pruned). A failed write
    # keeps the wider stored names, which can only over-refuse a later rename, so it is logged, not a failure.
    if db and express_name_suffix_plan is not None:   # EXP-8 RT B1: reached only after an HTTP 200 /deploy
        try:
            db.collection("workloads").document(product_id).set(
                {EXPRESS_DEPLOYED_NAME_PLAN_FIELD: express_name_suffix_plan(module_instances, product_id)},
                merge=True)
        except Exception as plan_err:
            logger.warning(f"Express workload {product_id}: deployed event-worker names not narrowed "
                           f"({type(plan_err).__name__}: {plan_err}); the stored names stay wider")

    # 6. Finalize in Firestore
    now_end = datetime.now(timezone.utc).isoformat()
    if db:
        try:
            db.collection("pipeline_executions").document(trace_id).set({
                "status": "COMPLETED",
                "current_stage": "ACTIVE",
                "completed_at": now_end,
                "stages": {
                    "terraform": {
                        "status": "SUCCESS",
                        "completed_at": now_end,
                        "summary": f"Deployed successfully. URL: {service_url or 'N/A'}",
                    },
                },
                "outputs": {
                    "service_url": service_url,
                    "github_repo": vended_repo,
                    "project_id": vended_pid,
                }
            }, merge=True)
            # EXP-7 RT B4: the deploy applied, so an earlier refusal is resolved
            # EXP-8 RT m1: an earlier failure's reason does not outlive a successful deploy
            final_doc = {"status": "ACTIVE", "service_url": service_url, "destroy_requires_approval": None,
                         "failure_reason": None}
            db.collection("workloads").document(product_id).set(final_doc, merge=True)
            logger.info(f"Express workload '{product_id}' successfully provisioned and marked ACTIVE.")
        except Exception as db_err:
            logger.error(f"Error finalizing express pipeline execution {trace_id}: {db_err}")


# ------------------------------------------------------------------------------------------------------------------
# FD-7M-a (owner 10-31): the workload's own region, from Settings > Approved Deployable Regions. Chosen at creation,
# recorded once on workloads/{pid}.region, never changed (OQ-23); legacy records without one follow the default region
# and are not stamped (OQ-24). Every check is exact set membership (no name guessing).
# ------------------------------------------------------------------------------------------------------------------
REGION_NOT_APPROVED = "REGION_NOT_APPROVED"
REGION_PROFILE_CONFLICT = "REGION_PROFILE_CONFLICT"
REGION_CHANGE_REFUSED = "REGION_CHANGE_REFUSED"
REGION_UNAVAILABLE = "REGION_UNAVAILABLE"


def _settings_contract():
    """The settings module whose models the strict read returned (it is loaded under more than one module name)."""
    from routes.settings import _current_settings_module
    mod = _current_settings_module()
    if mod is None or not callable(getattr(mod, "workload_region", None)):
        from shared import settings as mod  # the byte-identical replica in this service
    return mod


def _approved_regions_of(plat_settings: Any) -> Tuple[List[str], str, Any]:
    """(effective approved list, default region, orchestration) of a strict settings read."""
    orch = getattr(plat_settings, "orchestration", None)
    mod = _settings_contract()
    return mod.approved_deployable_regions(orch), mod.workload_region(None, orch), orch


def _region_http_error(status: int, error_class: str, region: Any, detail: str, **extra: Any) -> HTTPException:
    return HTTPException(status_code=status, detail={"error_class": error_class, "region": region, "detail": detail,
                                                     **extra})


def _refuse_region_profile_conflict(region: str, profile: Optional[str]) -> None:
    """OQ-25: a regulated profile whose allowed regions (schemas.PROFILE_ALLOWED_REGIONS, the compliance server's
    table) do not include the workload's region is refused at creation (422), not at the apply."""
    allowed = PROFILE_ALLOWED_REGIONS.get(profile) if profile else None
    if allowed is not None and region not in allowed:
        raise _region_http_error(422, REGION_PROFILE_CONFLICT, region,
                                 f"The {profile} security controls baseline allows only {', '.join(allowed)}; the "
                                 f"workload's region is {region}. Choose an allowed region or another baseline.",
                                 profile=profile, allowed_regions=list(allowed))


def _create_region(product_id: str, existing: Optional[Dict[str, Any]], requested: Optional[str], default_region: str,
                   orch: Any) -> Tuple[str, bool]:
    """(the workload's region, whether this create writes it). `existing` is the stored workload document ({} = new,
    None = unreadable). New -> the requested region or the default, written. A record with a region keeps it (another
    requested region: 409 REGION_CHANGE_REFUSED; a stored region no longer approved: 422 REGION_NOT_APPROVED). A
    legacy record without one keeps following the default and is not stamped (OQ-24). Unreadable: nothing written; a
    requested region cannot be confirmed -> 503."""
    if existing is None:
        if requested is not None:
            raise _region_http_error(503, REGION_UNAVAILABLE, requested,
                                     f"workloads/{product_id} could not be read, so its region cannot be recorded; "
                                     "nothing was created. Retry.")
        return default_region, False
    if not existing:
        return (requested if requested is not None else default_region), True
    stored = existing.get("region")
    effective = default_region if stored is None else stored
    if requested is not None and requested != effective:
        raise _region_http_error(409, REGION_CHANGE_REFUSED, requested,
                                 f"Workload '{product_id}' already deploys in {effective}; a workload keeps its "
                                 "region. Nothing was changed.", current_region=effective)
    if stored is not None:
        mod = _settings_contract()
        try:
            mod.workload_region(stored, orch, stage="control_center_create")
        except mod.RegionNotApproved as e:
            raise _region_http_error(422, REGION_NOT_APPROVED, stored, str(e), approved_regions=e.approved)
    return effective, False


def _record_express_region_failure(product_id: str, trace_id: str, error_class: str, detail: str) -> None:
    """FD-7M-a: the Express run stops before vending when the workload's region cannot be established; the pipeline
    and the workload are FAILED with the typed class and nothing is vended, synthesized or deployed."""
    logger.error(f"Express workload {product_id} stopped before vending ({error_class}): {detail}")
    if not db:
        return
    try:
        failed_at = datetime.now(timezone.utc).isoformat()
        skipped = {"status": "SKIPPED", "summary": f"Skipped: the workload region is not usable ({error_class})"}
        db.collection("pipeline_executions").document(trace_id).set({
            "status": "FAILED", "current_stage": "FAILED", "error_class": error_class, "error_message": detail,
            "completed_at": failed_at, "ended_at": failed_at,
            "stages": {"vending": dict(skipped), "hcl_synthesis": dict(skipped), "vcs_seed": dict(skipped),
                       "terraform": dict(skipped)},
        }, merge=True)
        db.collection("workloads").document(product_id).set({"status": "FAILED",
                                                             "failure_reason": f"{error_class}: {detail}"}, merge=True)
    except Exception as db_err:  # noqa: BLE001
        logger.error(f"Error recording the express region failure for {trace_id}: {db_err}")


def _express_workload_region(product_id: str, region: Optional[str]) -> Tuple[Optional[str], Optional[tuple]]:
    """FD-7M-a (F-D): the region an Express run deploys into, as (region, None) or (None, (error_class, detail)).
    The create route passes the region it resolved and recorded; without one, it is the record's region through the
    settings helper (no record region: the default region). Never the host $REGION or a literal."""
    if region:
        return region, None
    if not db:
        return None, (REGION_UNAVAILABLE, "no Firestore: the workload record cannot be read")
    try:
        snap = db.collection("workloads").document(product_id).get()
        record = (snap.to_dict() or {}) if getattr(snap, "exists", False) else {}
        plat = get_platform_settings(strict=True)
        mod = _settings_contract()
        return mod.workload_region(record.get("region") if isinstance(record, dict) else None,
                                   getattr(plat, "orchestration", None), stage="express"), None
    except Exception as e:  # noqa: BLE001 - classified below
        mod = _settings_contract()
        if isinstance(e, mod.RegionNotApproved):
            return None, (REGION_NOT_APPROVED, str(e))
        return None, (REGION_UNAVAILABLE, f"the workload region could not be established ({type(e).__name__}: {e})")


def _refuse_new_run_in_maintenance(action: str, settings: Any = None) -> None:
    """settings-toggles (FD-4AK Fable RT F5): every Control Center endpoint that starts a new run (create, retrigger,
    deploy-infra, deploy-to-folder, redeploy) calls this before any side effect. Maintenance mode on -> 503
    MAINTENANCE_MODE; settings unreadable / invalid -> 503 with the settings error code (fail closed). Runs already
    in flight, approvals, settings and decommission do not call it. `settings`: a strict read the caller already did."""
    refusal = (maintenance_refusal(settings, action) if settings is not None
               else new_run_refusal(action, read=get_platform_settings))
    if refusal is not None:
        logger.warning(f"{refusal['code']}: {action} refused")
        raise HTTPException(status_code=503, detail=refusal)


def _admit_new_build(product_id: str, trace_id: str, payload: Dict[str, Any], source: str, title: str,
                     request_id: Optional[str], now_iso: str) -> Optional["_build_admission.Admission"]:
    """BUILD-ADMISSION-QUEUE (G4): the slot of a new workload's first build (create form, promotion). Over the limit the
    run gets a QUEUED record and its feature request shows QUEUED. A refusal (store unavailable) marks the workload
    FAILED with the typed reason and raises (503): nothing is published. A Control Center without a Firestore client
    (None: it registered nothing either) leaves the decision to the gateway's intake admission, which every event
    passes: the event is published as before and the gateway queues it if no slot is free."""
    if db is None:
        logger.warning(f"Build {trace_id} of '{product_id}': no Firestore client on this Control Center; the gateway's "
                       f"intake admission decides its build slot")
        return None
    try:
        admission = build_queue.admit_run(
            db, trace_id=trace_id, product_id=product_id, payload=payload, source=source,
            request_status_on_dispatch="IN_PROGRESS",
            queued_record=_build_admission.queued_run_record(
                trace_id=trace_id, product_id=product_id, title=title, execution_mode="FULL", source=source,
                now_iso=now_iso, request_id=request_id))
    except HTTPException as refused:
        detail = refused.detail if isinstance(refused.detail, dict) else {"message": str(refused.detail)}
        if db is not None:
            try:
                db.collection("workloads").document(product_id).set(
                    {"status": "FAILED", "failure_reason": f"{detail.get('code', 'BUILD_ADMISSION')}: "
                                                           f"{detail.get('message', '')}"}, merge=True)
            except Exception as fs_err:  # noqa: BLE001 - the 503 below is the answer
                logger.error(f"Could not mark '{product_id}' FAILED after the build admission refusal: {fs_err}")
        raise
    if admission.state == _build_admission.QUEUED:
        build_queue.mark_request_queued(db, request_id, {"trace_id": trace_id, "queued_at": now_iso})
        if admission.pump_needed:
            build_queue.reconcile_and_pump(db)
    return admission


def _release_unpublished_build(trace_id: str) -> None:
    """BUILD-ADMISSION-QUEUE: a build whose event publish failed (not timed out) frees its slot. Logged on failure: the
    slot is then freed by the release rule (no workflow binds within the grace period)."""
    try:
        _build_admission.release(db, trace_id, reason="PUBLISH_FAILED")
        build_queue.reconcile_and_pump(db)
    except Exception as err:  # noqa: BLE001
        logger.error(f"{_build_admission.BUILD_ADMISSION_UNAVAILABLE}: slot of unpublished build {trace_id} not "
                     f"released now ({type(err).__name__}: {err})")


# RT14-19: typed outcomes of the FIRST build event of a new workload (create form, promotion). The workload record is
# already registered PROVISIONING and no run record exists yet, so a lost event used to leave it PROVISIONING forever
# (neither STALE-RUN nor BUILD_DISPATCH_LOST can see it). Classified by which step failed and the exception type only.
INTAKE_DISPATCH_UNAVAILABLE = "INTAKE_DISPATCH_UNAVAILABLE"            # no publisher / no platform project: 503
INTAKE_DISPATCH_FAILED = "INTAKE_DISPATCH_FAILED"                      # the publish definitely failed: 502
INTAKE_DISPATCH_OUTCOME_UNKNOWN = "INTAKE_DISPATCH_OUTCOME_UNKNOWN"    # the publish wait timed out: 504


def _fail_new_workload_dispatch(product_id: str, request_id: Optional[str], error_class: str, detail: str) -> None:
    """RT14-19: the new workload (and its initial feature request) FAILED with the typed class: nothing will build it.
    A failed write is logged; the typed HTTP error the caller raises is the answer either way."""
    if db is None:
        return
    failed_at = datetime.now(timezone.utc).isoformat()
    try:
        db.collection("workloads").document(product_id).set(
            {"status": "FAILED", "failure_reason": f"{error_class}: {detail}", "error_class": error_class,
             "failed_at": failed_at}, merge=True)
    except Exception as fs_err:  # noqa: BLE001
        logger.error(f"{error_class}: could not mark '{product_id}' FAILED ({type(fs_err).__name__}: {fs_err})")
    if request_id:
        try:
            db.collection("feature_requests").document(request_id).set(
                {"status": "FAILED", "error_class": error_class, "error": detail, "failed_at": failed_at}, merge=True)
        except Exception as fs_err:  # noqa: BLE001
            logger.error(f"{error_class}: could not mark request {request_id} FAILED ({type(fs_err).__name__})")


def _dispatch_first_build(*, product_id: str, pub_client: Any, current_project: str, intake_payload: Dict[str, Any],
                          source: str, title: str, request_id: Optional[str], now_iso: str,
                          response: Optional[Response]) -> Optional[Dict[str, Any]]:
    """RT14-19: the first build of a new workload (create form, promotion): build slot (BUILD-ADMISSION-QUEUE), then the
    intake event. Returns the build-queue view when the build waits for a slot (202), None when the event was
    published. Never answers success without a published (or queued) build:
    * no publisher / platform project -> workload FAILED INTAKE_DISPATCH_UNAVAILABLE, 503 (nothing admitted);
    * the publish failed -> slot released, workload FAILED INTAKE_DISPATCH_FAILED, 502;
    * the publish wait timed out -> 504 INTAKE_DISPATCH_OUTCOME_UNKNOWN with the trace id: the event may still be
      delivered, so the workload stays PROVISIONING, the slot is kept (freed by the release rule if no workflow binds)
      and the trace is recorded on the workload;
    * a typed admission refusal (503 / 409) propagates (the workload is already marked FAILED by the admission)."""
    trace_id = intake_payload["trace_id"]
    if not pub_client or not current_project:
        missing = "Pub/Sub publisher" if not pub_client else "platform project id"
        detail = f"no {missing} is configured on the Control Center, so the build event was not sent"
        logger.error(f"{INTAKE_DISPATCH_UNAVAILABLE}: '{product_id}' ({trace_id}): {detail}")
        _fail_new_workload_dispatch(product_id, request_id, INTAKE_DISPATCH_UNAVAILABLE, detail)
        raise HTTPException(status_code=503, detail={
            "code": INTAKE_DISPATCH_UNAVAILABLE, "error_class": INTAKE_DISPATCH_UNAVAILABLE, "trace_id": trace_id,
            "product_id": product_id, "message": f"Workload registered but no build was started: {detail}."})
    admission = _admit_new_build(product_id, trace_id, intake_payload, source, title, request_id, now_iso)
    if admission is not None and admission.state == _build_admission.QUEUED:
        if response is not None:
            response.status_code = 202
        return admission.view()
    intake_topic = f"projects/{current_project}/topics/spec-intake-events"
    try:
        future = pub_client.publish(intake_topic, json.dumps(intake_payload).encode("utf-8"))
        msg_id = future.result(timeout=10.0)
    except (TimeoutError, concurrent.futures.TimeoutError) as timeout_err:
        logger.error(f"{INTAKE_DISPATCH_OUTCOME_UNKNOWN}: build event of '{product_id}' ({trace_id}) timed out "
                     f"({type(timeout_err).__name__})")
        if db is not None:
            try:
                db.collection("workloads").document(product_id).set(
                    {"intake_dispatch": {"outcome": INTAKE_DISPATCH_OUTCOME_UNKNOWN, "trace_id": trace_id,
                                         "at": datetime.now(timezone.utc).isoformat()}}, merge=True)
            except Exception as fs_err:  # noqa: BLE001 - the 504 below carries the trace id
                logger.error(f"Could not record the unknown dispatch of '{product_id}' ({type(fs_err).__name__})")
        raise HTTPException(status_code=504, detail={
            "code": INTAKE_DISPATCH_OUTCOME_UNKNOWN, "error_class": INTAKE_DISPATCH_OUTCOME_UNKNOWN,
            "trace_id": trace_id, "product_id": product_id,
            "message": (f"The build event publish timed out and may still be delivered, so the build may already be "
                        f"running (trace {trace_id}). Check that run in the Flight Deck before retrying.")})
    except Exception as pub_err:  # noqa: BLE001 - typed below
        detail = f"build event publish failed ({type(pub_err).__name__}: {pub_err}); no workflow was started"
        logger.error(f"{INTAKE_DISPATCH_FAILED}: '{product_id}' ({trace_id}): {detail}")
        if db is not None:
            _release_unpublished_build(trace_id)
        _fail_new_workload_dispatch(product_id, request_id, INTAKE_DISPATCH_FAILED, detail)
        raise HTTPException(status_code=502, detail={
            "code": INTAKE_DISPATCH_FAILED, "error_class": INTAKE_DISPATCH_FAILED, "trace_id": trace_id,
            "product_id": product_id, "message": f"Workload registered but build dispatch failed: {detail}."})
    logger.info(f"Dispatched intake event for workload '{product_id}' ({source}, Msg ID: {msg_id})")
    return None


EXPRESS_DESTROY_REQUIRES_APPROVAL = "DESTROY_REQUIRES_APPROVAL"


def _destroy_approval_refusal(tf_resp: Any) -> Optional[Dict[str, Any]]:
    """EXP-7: the terraform service's typed 409 body (`detail.error_class == DESTROY_REQUIRES_APPROVAL`), else None.
    Read from the JSON detail object only, never from an error string."""
    try:
        body = tf_resp.json()
    except Exception:
        return None
    detail = body.get("detail") if isinstance(body, dict) else None
    if not isinstance(detail, dict) or detail.get("error_class") != EXPRESS_DESTROY_REQUIRES_APPROVAL:
        return None
    addresses = detail.get("removal_addresses")
    if not isinstance(addresses, list) or not all(isinstance(a, str) for a in addresses):
        addresses = []
    return {"error_class": EXPRESS_DESTROY_REQUIRES_APPROVAL, "error": str(detail.get("error") or ""),
            "removal_addresses": sorted(addresses),
            "approved_removals": [a for a in (detail.get("approved_removals") or []) if isinstance(a, str)]}


EXPRESS_DEPLOY_FAILED = "EXPRESS_DEPLOY_FAILED"
# EXP-8 RT M1: a /deploy call that timed out may still finish its apply server-side; decided by exception type only
EXPRESS_DEPLOY_OUTCOME_UNKNOWN = "EXPRESS_DEPLOY_OUTCOME_UNKNOWN"
# EXP-8 RT M1: the client waits as long as the terraform service itself may run a request (its Cloud Run request
# timeout, `infra/platform/main.tf`), so a slow but successful apply (e.g. a Cloud SQL create) is not cut off.
EXPRESS_DEPLOY_TIMEOUT_SECONDS = 1800.0


def _is_transport_timeout(err: BaseException) -> bool:
    """EXP-8 RT M1: an httpx timeout (read/connect/write/pool), by type only."""
    try:
        import httpx
    except ImportError:
        return False
    return isinstance(err, httpx.TimeoutException)


def _is_error_class(value: Any) -> bool:
    """A typed error class: identifiers joined by dots (`BILLING_NOT_LINKED`, `VENDING.PARENT_FOLDER_UNCONFIGURED`).
    Format validation of a typed field (RT 11-07 F2: `str.isidentifier()` dropped every dotted `VENDING.*` class)."""
    return isinstance(value, str) and bool(value) and all(part.isidentifier() for part in value.split("."))


def _express_vending_failure(v_resp: Any) -> Optional[Dict[str, Any]]:
    """FD-4AI: the typed failure of a non-200 Express `/vend-all` answer, or None. Only a body whose
    `detail.error_class` is set (vending's VendingFailure, e.g. BILLING_NOT_LINKED) is a typed failure; any other
    answer keeps today's behaviour. Message text is only displayed, never read to classify."""
    if v_resp is None:
        return None
    try:
        body = v_resp.json()
    except Exception:
        return None
    detail = body.get("detail") if isinstance(body, dict) else None
    error_class = detail.get("error_class") if isinstance(detail, dict) else None
    if not _is_error_class(error_class):
        return None
    message = detail.get("detail")
    http_status = getattr(v_resp, "status_code", None)
    return {"error_class": error_class,
            "http_status": http_status if isinstance(http_status, int) else None,
            "error": message if isinstance(message, str) and message else f"Vending returned HTTP {http_status}."}


def _record_express_vending_failure(product_id: str, trace_id: str, failure: Dict[str, Any]) -> None:
    error_class, detail = failure["error_class"], failure["error"]
    logger.error(f"Vending failed for express workload {product_id} ({error_class}): {detail}")
    if not db:
        return
    try:
        failed_at = datetime.now(timezone.utc).isoformat()
        skipped = {"status": "SKIPPED", "summary": "Skipped: project vending failed"}
        db.collection("pipeline_executions").document(trace_id).set({
            "status": "FAILED",
            "current_stage": "FAILED",
            "error_class": error_class,
            "error_message": detail,
            "completed_at": failed_at,
            "ended_at": failed_at,
            "stages": {
                "vending": {"status": "FAILED", "completed_at": failed_at, "error_class": error_class,
                            "summary": detail},
                "hcl_synthesis": dict(skipped),
                "vcs_seed": dict(skipped),
                "terraform": dict(skipped),
            },
        }, merge=True)
        db.collection("workloads").document(product_id).set({
            "status": "FAILED",
            "failure_reason": f"{error_class}: {detail}",
        }, merge=True)
    except Exception as db_err:
        logger.error(f"Error recording failed express vending for {trace_id}: {db_err}")


def _express_deploy_failure(tf_resp: Any, transport_error: Optional[BaseException] = None) -> Dict[str, Any]:
    """EXP-8: the typed reason of a non-success Express `/deploy` outcome (`tf_resp` None = no response).
    The class is the response's typed `detail.error_class` when it has one, else EXPRESS_DEPLOY_FAILED with the HTTP
    status (None when there was no response). Message text is only displayed, never read to classify."""
    if tf_resp is None:
        if transport_error is not None and _is_transport_timeout(transport_error):
            error = (f"The terraform service /deploy call timed out ({type(transport_error).__name__}) after "
                     f"{int(EXPRESS_DEPLOY_TIMEOUT_SECONDS)} s. The apply may still finish; check the workload's "
                     "deployment before re-submitting.")
            return {"error_class": EXPRESS_DEPLOY_OUTCOME_UNKNOWN, "http_status": None, "error": error}
        if transport_error is not None:
            error = (f"The terraform service /deploy call raised {type(transport_error).__name__}: {transport_error}. "
                     "Whether the apply ran is unknown; check the workload before re-submitting.")
        else:
            error = "The terraform service URL is not configured or could not be discovered; nothing was deployed."
        return {"error_class": EXPRESS_DEPLOY_FAILED, "http_status": None, "error": error}
    http_status = getattr(tf_resp, "status_code", None)
    http_status = http_status if isinstance(http_status, int) else None
    try:
        body = tf_resp.json()
    except Exception:
        body = None
    detail = body.get("detail") if isinstance(body, dict) else None
    error_class = detail.get("error_class") if isinstance(detail, dict) else None
    if not _is_error_class(error_class):
        error_class = EXPRESS_DEPLOY_FAILED
    message = detail.get("error") if isinstance(detail, dict) else detail
    error = (message if isinstance(message, str) and message
             else f"The terraform service /deploy returned HTTP {http_status}.")
    return {"error_class": error_class, "http_status": http_status, "error": error}


def _record_express_terraform_failed(product_id: str, trace_id: str, error_class: str, detail: str,
                                     http_status: Optional[int] = None,
                                     execution_extra: Optional[Dict[str, Any]] = None,
                                     workload_extra: Optional[Dict[str, Any]] = None,
                                     failed_at: Optional[str] = None) -> None:
    """EXP-7/EXP-8: the one place an Express deploy that did not succeed is recorded: the terraform stage, the
    pipeline and the workload are FAILED with the typed `error_class`."""
    if not db:
        return
    try:
        failed_at = failed_at or datetime.now(timezone.utc).isoformat()
        stage = {"status": "FAILED", "completed_at": failed_at, "error_class": error_class, "summary": detail}
        if http_status is not None:
            stage["http_status"] = http_status
        db.collection("pipeline_executions").document(trace_id).set({
            "status": "FAILED",
            "current_stage": "FAILED",
            "error_class": error_class,
            "error_message": detail,
            "completed_at": failed_at,
            "ended_at": failed_at,
            "stages": {"terraform": stage},
            **(execution_extra or {}),
        }, merge=True)
        db.collection("workloads").document(product_id).set({
            "status": "FAILED",
            "failure_reason": f"{error_class}: {detail}",
            **(workload_extra or {}),
        }, merge=True)
    except Exception as db_err:
        logger.error(f"Error recording the failed express deploy for {trace_id}: {db_err}")


def _stored_repo_name(value: Any) -> Optional[str]:
    """WORKLOAD-REPO-NAME (10-27, seen live: the Workloads Catalog was empty on both dev installs): a workload's
    `github_repo` is the repository's full name (a string). The Express create path stored the vending service's whole
    repository result (a dict) there, which failed WorkloadSummary validation and emptied the catalog. Typed read:
    a string is returned as is, a vending repository result gives its `full_name`, anything else is None."""
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        full_name = value.get("full_name")
        return full_name if isinstance(full_name, str) and full_name else None
    return None


def _workload_repo_for_feature_request(product_id: str) -> Optional[str]:
    """GITHUB-REPO-NAME-NO-PREFIX (owner 11-12): the repository of a feature request that stores none: the workload
    record's `github_repo` (a workload vended before 11-12 keeps its `castor-<id>` repository), else the workload's
    default repository in the configured owner (shared default_repository_name, through resolve_repo_identity), else
    None (no owner configured). Read only; an unreadable record is logged and falls through to the default."""
    if db:
        try:
            snap = db.collection("workloads").document(product_id).get()
            record = snap.to_dict() if snap.exists else None
            stored = _stored_repo_name(record.get("github_repo")) if isinstance(record, dict) else None
            if stored:
                return stored
        except Exception as e:  # noqa: BLE001 - display link only; the default repository is shown instead
            logger.warning(f"Could not read workloads/{product_id} for its repository: {type(e).__name__}")
    owner = github_owner()
    return resolve_repo_identity(None, default_owner=owner, product_id=product_id)[2] if owner else None


def _recorded_region(data: Dict[str, Any]) -> Optional[str]:
    """FD-7M-a / SAT-44 (display): the region recorded on `workloads/{pid}` at creation. Typed read like
    `_stored_repo_name`: a non-empty string is returned as is; missing or any other value is None (a workload created
    before regions were recorded, which follows the Settings default region). Never fails the catalog."""
    value = data.get("region") if isinstance(data, dict) else None
    return value if isinstance(value, str) and value else None


def _express_service_url(tf_data: Dict[str, Any], module_instances: List[Any]) -> str:
    """EXPRESS-SERVICE-URL (10-27, seen live on a release-candidate install): the primary service URL of a
    successful Express deploy. Express names its Cloud Run outputs `compute_<instance>_uri` and has no `service_url` / `service_uri`
    root output, so the deploy result's generic `service_url` was empty ("URL: N/A"). The primary service is the
    first compute-cloudrun instance in the request's typed module order (shared.express_synthesizer.
    express_primary_service_output); its URL is read from the deploy result's `outputs` by that exact output name.
    Falls back to the result's own `service_url` when the request has no Cloud Run instance or that output is
    missing or not a string. Never inspects output names or values beyond the exact typed key."""
    fallback = tf_data.get("service_url") or ""
    name = express_primary_service_output(module_instances) if express_primary_service_output is not None else None
    outputs = tf_data.get("outputs")
    if not name or not isinstance(outputs, dict):
        return fallback
    entry = outputs.get(name)
    value = entry.get("value") if isinstance(entry, dict) else None
    return value if isinstance(value, str) and value else fallback


def _record_express_deploy_failure(product_id: str, trace_id: str, failure: Dict[str, Any]) -> None:
    """EXP-8: a non-success `/deploy` (other than EXP-7's typed refusal) leaves the workload FAILED, never ACTIVE."""
    logger.error(f"Express deploy of '{product_id}' failed ({failure['error_class']}, HTTP {failure['http_status']})")
    _record_express_terraform_failed(product_id, trace_id, failure["error_class"], failure["error"],
                                     http_status=failure["http_status"])


def express_destroy_refusal_open(workload: Any) -> bool:
    """EXP-7 RT B1 / RT14-07: True while an Express workload's last deploy was refused with DESTROY_REQUIRES_APPROVAL
    and no Express re-submit has cleared it (`destroy_requires_approval` is a non-empty dict). The gateway's
    /governance/deploy-only-gate applies the same rule (`_express_destroy_refusal_open` there)."""
    if not isinstance(workload, dict) or workload.get("creation_mode") != "EXPRESS":
        return False
    open_refusal = workload.get("destroy_requires_approval")
    return isinstance(open_refusal, dict) and bool(open_refusal)


def _refuse_open_express_destroy_refusal(workload: Dict[str, Any]) -> None:
    """EXP-7 RT B1 / RT14-07: the ONE check every Control Center path that can start a DEPLOY_ONLY (Fast-Path) run calls
    before it writes or publishes anything. The refused Express HCL is already committed to the workload's branch, and
    a DEPLOY_ONLY re-apply carries no destroy policy, so it would apply the deletions the operator never approved.
    409 DESTROY_REQUIRES_APPROVAL until an Express re-submit clears the refusal."""
    if not express_destroy_refusal_open(workload):
        return
    open_refusal = workload.get("destroy_requires_approval") or {}
    raise HTTPException(status_code=409, detail={
        "error_class": EXPRESS_DESTROY_REQUIRES_APPROVAL,
        "removal_addresses": [a for a in (open_refusal.get("removal_addresses") or []) if isinstance(a, str)],
        "detail": ("This Express workload's last deploy was refused because it would delete or replace existing "
                   "resources, and that configuration is committed. Re-submit it in Express mode without the "
                   "change, or with approved_removals set to exactly these addresses."),
    })


def _record_express_destroy_refusal(product_id: str, trace_id: str, refusal: Dict[str, Any]) -> None:
    """EXP-7: nothing was applied. The pipeline and the workload are FAILED with DESTROY_REQUIRES_APPROVAL and the
    exact addresses the operator would have to approve (re-submit with approved_removals = removal_addresses)."""
    addresses = refusal["removal_addresses"]
    detail = (f"The deploy would delete or replace {len(addresses)} existing resource(s): {addresses}. Nothing was "
              "applied. Re-submit without the change, or approve by re-submitting with approved_removals set to "
              "exactly these addresses.")
    logger.warning(f"Express deploy of '{product_id}' refused ({EXPRESS_DESTROY_REQUIRES_APPROVAL}): {addresses}")
    failed_at = datetime.now(timezone.utc).isoformat()
    _record_express_terraform_failed(
        product_id, trace_id, EXPRESS_DESTROY_REQUIRES_APPROVAL, detail,
        execution_extra={"destroy_requires_approval": {"removal_addresses": addresses,
                                                       "approved_removals": refusal["approved_removals"]}},
        workload_extra={"destroy_requires_approval": {"removal_addresses": addresses, "trace_id": trace_id,
                                                      "refused_at": failed_at}},
        failed_at=failed_at)


def _guard_compliance_downgrade(product_id: str, requested: str, admin_email: str, now_iso: str) -> None:
    """Owner decision 10-18 (row CP-11): re-submitting an existing workload with a less strict profile than its stored
    regulated one is not stored. An admin approval card (approval_requests/appr-cpdown-{pid}-{from}-{to}) is created
    and the request is refused (409) until an admin approves it. Same card id and record as the gateway
    (compliance_agent/profiles.py)."""
    if not db:
        return
    try:
        snap = db.collection("workloads").document(product_id).get()
        data = snap.to_dict() if getattr(snap, "exists", False) is True else None
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Could not read the workload's compliance profile: {e}")
    stored = data.get("requested_compliance_profile") if isinstance(data, dict) else None
    if not isinstance(stored, str) or not profile_is_downgrade(stored, requested):
        return
    approval_id = f"appr-cpdown-{product_id}-{stored}-{requested}".lower()
    record = {
        "approval_id": approval_id,
        "approval_type": "COMPLIANCE_PROFILE_DOWNGRADE",
        "product_id": product_id,
        "trace_id": "",
        "status": "PENDING",
        "from_profile": stored,
        "to_profile": requested,
        "requested_via": "control_center",
        "requested_by": admin_email,
        "cost_delta_monthly": "$0.00/mo",
        "risk_assessment": (f"Compliance profile downgrade for {product_id}: {stored} -> {requested}. "
                            "APPROVE (admin only) stores the new profile; the next run uses it. REJECT keeps "
                            f"{stored}."),
        "created_at": time.time(),
        "created_at_iso": now_iso,
        "requested_at": now_iso,
    }
    try:
        ref = db.collection("approval_requests").document(approval_id)
        existing = ref.get()
        if getattr(existing, "exists", False) is not True:
            ref.set(record)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Could not create the compliance downgrade approval: {e}")
    raise HTTPException(status_code=409, detail={
        "error_class": "COMPLIANCE_DOWNGRADE_REQUIRES_APPROVAL",
        "approval_id": approval_id,
        "detail": f"Downgrading {product_id} from {stored} to {requested} needs an admin approval ({approval_id}).",
    })


def _guard_express_worker_renames(product_id: str, module_instances: List[Any]) -> Tuple[bool, Optional[List[Any]]]:
    """EXP-6: refuses (409, typed error_class) an Express request that would change the name suffix of an event
    worker OpenTofu may manage for the existing workload (shared.express_synthesizer.refuse_worker_renames; the
    stored names are typed data on the workload record, never derived from resource names).
    Returns (first_create, names_to_store): first_create is True when no workload record exists (the caller marks the
    record as name-plan tracked); names_to_store, when not None, is the stored names plus this request's
    (merge_name_plans), which the caller puts in its workload write (RT F1/F2: covers a request still provisioning
    and a failed /deploy; a successful /deploy narrows it).
    A request whose own name plan is refused (collision, invalid suffix, name too long) is left to the synthesis
    stage, which records that refusal as today (EXP-5); nothing is stored for it. A request without event workers
    cannot rename one: a failed read then does not stop it (as before EXP-6); with event workers a failed read is a
    503 (fail closed)."""
    if not db or express_name_suffix_plan is None or refuse_worker_renames is None or merge_name_plans is None:
        return False, None
    instances = [inst.model_dump() if hasattr(inst, "model_dump") else inst for inst in module_instances]
    try:
        new_plan = express_name_suffix_plan(instances, product_id)
    except ExpressSynthesisRefused:
        new_plan = None
    try:
        snap = db.collection("workloads").document(product_id).get()
        exists = getattr(snap, "exists", False) is True
        record = (snap.to_dict() or {}) if exists else None
    except Exception as e:
        if new_plan:
            raise HTTPException(status_code=503, detail=f"Could not read the existing workload's worker names: {e}")
        return False, None
    if record is not None and not isinstance(record, dict):
        record = {}
    if not new_plan:
        return record is None, None
    try:
        refuse_worker_renames(record, new_plan)
    except ExpressSynthesisRefused as refused:
        raise HTTPException(status_code=409, detail={"error_class": refused.reason, "detail": str(refused)})
    return record is None, merge_name_plans(record, new_plan)


def _verified_cc_submitter(request: Request) -> Optional[str]:
    """``user:<email>`` of the human identity the CC auth layer verified for this request (IAP assertion or session
    cookie, ``request.state.auth_method``), or None: never a form field, the spec or a source workload's record. A
    platform-caller bearer, a service account or no verified human -> None."""
    return (verified_submitter_member(getattr(request.state, "user_email", None))
            if getattr(request.state, "auth_method", None) in ("iap", "session") else None)


def _verified_submitter_fields(request: Request) -> Dict[str, Any]:
    """APP-ADMIN-DEFAULT (owner 11-16): ``{verified_submitter: submitter_provenance(<member>, "control_center_auth")}``
    for a NEW workload document whose access the submitter chose (intake), {} without a verified human. The developer
    and QA read it (shared.access_policy.workload_verified_submitter) only to default the app administrators of a
    Direct IAP Cloud Run workload to that submitter, when the record lists none and the submitter is an exact
    ``user:`` invoker. It is written once, at create; a re-create of an existing workload never changes it."""
    submitter = _verified_cc_submitter(request)
    return {VERIFIED_SUBMITTER_FIELD: submitter_provenance(submitter, "control_center_auth")} if submitter else {}


def _default_access_fields(request: Request) -> Dict[str, Any]:
    """OSS-D23 (owner 10-19/10-20): the private platform default for a NEW Agent-mode workload document created by a
    Control Center route: ``access`` = ``platform_default_access_record(submitter)`` plus, when a submitter is listed,
    its provenance (``control_center_auth``). The submitter is ONLY the human identity the CC auth layer verified (IAP
    assertion or session cookie, ``request.state.auth_method``); never a form field, the spec or a source workload's
    record. A platform-caller bearer or no verified human -> nobody listed (the build stops for an operator)."""
    submitter = _verified_cc_submitter(request)
    fields: Dict[str, Any] = {"access": platform_default_access_record(submitter)}
    if submitter is not None:
        fields[SUBMITTER_PROVENANCE_FIELD] = submitter_provenance(submitter, "control_center_auth")
    return fields


def _freeze_new_workloads(read: Any) -> bool:
    """FD-4CU (owner 10-21): governance.freeze_new_workloads, the initial ``code_freeze`` of a NEW workload. True
    unless the setting is exactly False on a strict read (`read` is called like get_platform_settings); missing ->
    the default (True); unreadable / invalid / reader missing -> True, logged. Never raises: creating a workload never
    fails because of this read."""
    try:
        from shared.settings import freeze_new_workloads_enabled
    except Exception as e:  # noqa: BLE001
        logger.warning(f"governance.freeze_new_workloads reader unavailable ({type(e).__name__}: {e}); "
                       "the new workload starts frozen.")
        return True
    try:
        return freeze_new_workloads_enabled(read=read)
    except Exception as e:  # noqa: BLE001 - the reader never raises; belt and braces
        logger.warning(f"governance.freeze_new_workloads could not be read ({type(e).__name__}: {e}); "
                       "the new workload starts frozen.")
        return True


def _platform_default_budget_usd(plat_settings: Any) -> float:
    """FD-4CI-b: finops.default_monthly_budget_usd of the settings the create path read strictly. A settings object
    without a usable value (a stub with no FinOps section) gets the schema default."""
    value = getattr(getattr(plat_settings, "finops", None), "default_monthly_budget_usd", None)
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
        return float(value)
    try:
        from shared.settings import FinOpsSettings
        return float(FinOpsSettings().default_monthly_budget_usd)
    except Exception:  # noqa: BLE001 - no settings module: the documented schema default
        return 40.0


# FD-4CU / FD-4CU-b (owner 10-21): the initial governance fields a re-create of an existing workload keeps.
KEPT_ON_RECREATE = ("code_freeze", "sre_auto_healing_enabled", "refactor_scanner_enabled")


def _stored_workload_doc(product_id: str) -> Optional[Dict[str, Any]]:
    """FD-4CU: the workload document as stored before a create writes it: {} when there is none (a new workload),
    None when it cannot be read (the caller then writes no field it would keep: it never turns SRE auto-healing or the
    scanner back on, and only ever freezes)."""
    if not db:
        return {}
    try:
        snap = db.collection("workloads").document(product_id).get()
    except Exception as e:  # noqa: BLE001
        logger.warning(f"workloads/{product_id} unreadable before create ({type(e).__name__}: {e}); its freeze is "
                       "only ever turned on and its SRE / scanner switches are not written by this request.")
        return None
    data = (snap.to_dict() or {}) if getattr(snap, "exists", False) else {}
    return data if isinstance(data, dict) else {}


def _new_workload_branch(product_id: str, stored: Optional[Dict[str, Any]], read: Any) -> str:
    """FD-4CI-b-R1: the branch of a workload whose create request names none. `stored` is the workload document the
    create already read ({} = none, None = unreadable; no extra read here). A document that already records a branch
    keeps it (a re-create); a new workload gets Settings > Default GitHub Branch from the strict read the caller made
    (`read` is called like get_platform_settings); "main" -- the branch before the setting was applied -- when the
    stored document cannot be read, the reader is missing or the setting is unreadable / not a plain branch name
    (logged). Never raises."""
    if stored is None:
        logger.warning(f"workloads/{product_id} unreadable before create; its branch is main.")
        return "main"
    recorded = stored.get("default_branch")
    if isinstance(recorded, str) and recorded:
        return recorded
    try:
        from shared.settings import default_branch_setting
        return default_branch_setting(read=read)
    except Exception as e:  # noqa: BLE001 - reader missing: the branch before the setting was applied
        logger.warning(f"orchestration.default_branch reader unavailable ({type(e).__name__}: {e}); using main.")
        return "main"


def _platform_default_breach_policy(plat_settings: Any) -> str:
    """FD-4CI-b (10): the policy a workload created with "Platform Default" (no budget_breach_policy) gets: the
    platform's finops.default_breach_policy, stored as its plain string value (what the budget enforcer reads)."""
    policy = getattr(getattr(plat_settings, "finops", None), "default_breach_policy", None)
    return str(getattr(policy, "value", policy) or "AUTONOMOUS_SCALE_TO_ZERO")


def _apply_create_gha_switch(product_id: str, requested: Optional[bool], vcs_provider: str,
                             record: Dict[str, Any], stored: Optional[Dict[str, Any]]) -> None:
    """GHA-DEPLOY-SWITCH at create. Serverless Git: false is refused (422 GHA_DEPLOY_SWITCH_NOT_GITHUB), nothing is
    stored. GitHub: a new workload (`stored` == {}) stores `requested` (None = true); an existing one stores nothing,
    and an answer different from the stored switch is refused (409, use the PATCH); an unreadable document (None) with
    an answer is 503 GHA_DEPLOY_SWITCH_UNAVAILABLE (without one, nothing is written, as before)."""
    if vcs_provider == "SERVERLESS_GIT":
        if requested is False:
            raise HTTPException(status_code=422, detail={
                "error_class": "GHA_DEPLOY_SWITCH_NOT_GITHUB",
                "detail": "github_actions_deploy applies to GitHub workloads only; Serverless Git workloads deploy "
                          "through the platform's pipeline already."})
        return
    if stored == {}:
        record[GITHUB_ACTIONS_DEPLOY_FIELD] = True if requested is None else bool(requested)
        return
    if requested is None:
        return
    if stored is None:   # RT SAT-16/34 F5: an unreadable document is 503, as every other read failure here
        raise HTTPException(status_code=503, detail={
            "error_class": "GHA_DEPLOY_SWITCH_UNAVAILABLE",
            "detail": f"workloads/{product_id} could not be read, so its GitHub Actions deploy switch is unknown; "
                      "nothing was written. Retry when Firestore is reachable."})
    current = _gha_deploy_switch(stored, vcs_provider)
    if current is not requested:
        raise HTTPException(status_code=409, detail={
            "error_class": "GHA_DEPLOY_SWITCH_CHANGE_NEEDS_PATCH",
            "detail": f"Workload '{product_id}' already exists"
                      + (" and its stored GitHub Actions deploy switch is not true or false" if current is None else
                         f" with GitHub Actions deploy {'on' if current else 'off'}")
                      + f"; use PATCH /api/workloads/{product_id}/github-actions-deploy (administrator, audited)."})


@router.post("/api/workloads", response_model=WorkloadSummary, dependencies=[require(ADMIN)])
def create_workload(req: CreateWorkloadRequest, request: Request, background_tasks: BackgroundTasks = None,
                    response: Response = None):
    verify_admin_access(request)
    """
    Submits a new full workload specification to StackVend:
    1. Validates and registers the workload in Firestore
    2. Persists the initial architecture specification in feature_requests
    3. If creation_mode == 'EXPRESS', executes deterministic HCL synthesis & deployment pipeline
    4. If creation_mode == 'AGENT', dispatches spec intake event to Pub/Sub for autonomous multi-agent swarm
    """
    admin_email = getattr(request.state, "user_email", "admin-console")

    raw_pid = req.product_id.strip().lower()
    clean_pid = re.sub(r"[^a-z0-9\-]", "-", raw_pid).strip("-")
    if not clean_pid:
        raise HTTPException(status_code=400, detail="Invalid product_id: must contain alphanumeric characters or hyphens.")
    # RT14-37 / RT14-02: the id every intake entry point now requires (an RFC 1123 label, never the platform's own),
    # checked before anything is registered (the gateway would refuse the build event after registration).
    try:
        validate_product_id(clean_pid)
    except UnsafePathError:
        raise HTTPException(status_code=400, detail="Invalid product_id: at most 63 lowercase letters, digits and "
                                                    "hyphens, starting and ending with a letter or digit.") from None
    if clean_pid in PLATFORM_PSEUDO_WORKLOADS:
        raise HTTPException(status_code=400, detail=f"Invalid product_id: '{clean_pid}' is reserved for the platform.")

    is_express = (str(req.creation_mode or "").strip().upper() == "EXPRESS")
    # FD-4CS: the Express synthesizer applies the access record to every Cloud Run service (L19-11 RT F3 is resolved),
    # so `access` is accepted for Express as for Agent mode.
    if req.approved_removals and not is_express:
        # EXP-7: approved_removals belongs to the Express destroy approval only; never silently ignored
        raise HTTPException(status_code=422, detail={
            "error_class": "APPROVED_REMOVALS_EXPRESS_ONLY",
            "detail": "approved_removals applies to Express deploys only (EXP-7)."})

    # Generate default spec content for Express mode if empty
    spec_text = (req.spec_content or "").strip()
    if not spec_text and is_express:
        instances_desc = ", ".join(
            (inst.instance_name if hasattr(inst, "instance_name") else inst.get("instance_name", "instance"))
            for inst in (req.module_instances or [])
        )
        spec_text = f"Express Registered Modules Workload: {instances_desc or 'Foundation'}"
    elif not spec_text:
        spec_text = f"Workload specification for {clean_pid}"

    current_project = project_id or os.getenv("PROJECT_ID", "")
    clean_base = re.sub(r"[^a-z0-9]", "-", clean_pid.lower()).strip("-")
    if 6 <= len(clean_base) <= 30 and clean_base[0].isalpha():
        target_project_id = clean_base
    else:
        clean_prefix = clean_base[:23].rstrip("-") if len(clean_base) > 23 else clean_base
        if not clean_prefix or not clean_prefix[0].isalpha():
            clean_prefix = f"p-{clean_prefix}".rstrip("-")[:23]
        target_project_id = f"{clean_prefix}-{uuid.uuid4().hex[:6]}".strip("-")[:30].rstrip("-")
    now_iso = datetime.now(timezone.utc).isoformat()

    # Resolve VCS Provider (workload override > platform settings > env > default GITHUB)
    chosen_vcs = req.vcs_provider
    default_hitl = True
    default_plan_approval = False
    plat_settings = None
    try:
        # FD-4AK: the intake defaults (code review, plan approval, breach policy) are governance; a settings document
        # that cannot be read or does not validate refuses the request (503) -- never compile-time defaults, which
        # would turn plan approval off.
        plat_settings = get_platform_settings(strict=True)
        gov = getattr(plat_settings, "governance", None)
        default_hitl = getattr(gov, "default_require_human_code_review", True) if gov else True
        default_plan_approval = getattr(gov, "require_plan_approval", False) if gov else False
        if not chosen_vcs:
            chosen_vcs = getattr(plat_settings, "vcs_provider", None) or getattr(getattr(plat_settings, "governance", None), "vcs_provider", None)
    except Exception as settings_err:  # noqa: BLE001
        logger.error(f"Workload '{clean_pid}' refused: platform settings unavailable "
                     f"({type(settings_err).__name__}: {settings_err})")
        raise HTTPException(status_code=503, detail={
            "code": getattr(settings_err, "code", "PLATFORM_SETTINGS_UNAVAILABLE"),
            "message": "Platform governance settings could not be read or are invalid; the workload was not "
                       "created. Fix the settings (Settings page) or retry when Firestore is reachable.",
            "errors": list(getattr(settings_err, "errors", None) or []),
        })
    # settings-toggles: maintenance mode refuses every new workload (form, API, Express) before any record is written.
    _refuse_new_run_in_maintenance("workload creation", plat_settings)
    # FD-7M-a: a requested region outside Settings > Approved Deployable Regions, or outside the chosen regulated
    # baseline's regions (OQ-25), is refused here, before anything is written or vended.
    try:
        approved_regions, default_region, orch_settings = _approved_regions_of(plat_settings)
    except Exception as region_err:  # noqa: BLE001 - the strict read returned no usable orchestration section
        raise _region_http_error(503, REGION_UNAVAILABLE, req.region,
                                 f"The approved deployable regions could not be read ({type(region_err).__name__}); "
                                 "the workload was not created.")
    if req.region is not None:
        if req.region not in approved_regions:
            raise _region_http_error(422, REGION_NOT_APPROVED, req.region,
                                     f"Region {req.region!r} is not an approved deployable region "
                                     f"({', '.join(approved_regions)}); an administrator adds regions in Settings. "
                                     "Nothing was created.", approved_regions=approved_regions)
        _refuse_region_profile_conflict(req.region, req.compliance_profile.value if req.compliance_profile else None)
    # FD-4CU (owner 10-21): a new workload starts with Code Freeze on while governance.freeze_new_workloads is on
    # (default). Read from the strict read above; it never refuses the request. An existing record keeps its value
    # (see the write below).
    freeze_on_create = _freeze_new_workloads(lambda **_k: plat_settings)

    if req.auto_merge is not None:
        chosen_require_review = not req.auto_merge
    elif req.require_human_code_review is not None:
        chosen_require_review = req.require_human_code_review
    else:
        chosen_require_review = default_hitl

    if req.require_plan_approval is not None:
        chosen_plan_approval = bool(req.require_plan_approval)
    else:
        chosen_plan_approval = bool(default_plan_approval)

    if not chosen_vcs:
        chosen_vcs = os.getenv("VCS_PROVIDER", "GITHUB")
    clean_vcs_provider = str(chosen_vcs).strip().upper()
    if clean_vcs_provider not in ("GITHUB", "SERVERLESS_GIT"):
        clean_vcs_provider = "GITHUB"

    if clean_vcs_provider == "SERVERLESS_GIT":
        if req.github_repo and req.github_repo.strip():
            full_github_repo = req.github_repo.strip()
        else:
            full_github_repo = f"serverless-git/{clean_pid}.git"
    else:
        if req.github_repo and "/" in req.github_repo:
            full_github_repo = req.github_repo.strip()
        elif req.github_repo:
            full_github_repo = f"{require_github_owner()}/{req.github_repo.strip()}"
        else:
            full_github_repo = f"{require_github_owner()}/{clean_pid}"

    # FD-4CI-b: a request without a budget gets the platform's Default Monthly Budget Ceiling (from the strict read
    # above: unreadable settings already refused the request).
    budget = (float(req.budget_ceiling_monthly_usd) if req.budget_ceiling_monthly_usd
              else _platform_default_budget_usd(plat_settings))

    # Resolve IaC Engine (workload override > platform settings > default OPENTOFU)
    clean_engine = str(req.iac_engine or "").strip().upper()
    if clean_engine not in ("OPENTOFU", "TERRAFORM"):
        try:
            clean_engine = getattr(plat_settings.orchestration, "default_iac_engine", "OPENTOFU")
        except Exception:
            clean_engine = "OPENTOFU"
    if clean_engine not in ("OPENTOFU", "TERRAFORM"):
        clean_engine = "OPENTOFU"

    # Resolve destination GCP folder
    target_folder = req.folder_id
    folder_name = None
    if not target_folder and db:
        try:
            default_folders = list(db.collection("managed_folders").where("is_default", "==", True).limit(1).stream())
            if default_folders:
                target_folder = default_folders[0].to_dict().get("folder_id")
                folder_name = default_folders[0].to_dict().get("display_name")
        except Exception:
            pass

    # FD-4AY / red-team H9: the root comes only from MANAGED_WORKLOADS_FOLDER_ID, and any other destination
    # (request, or the agent-writable Firestore default) must be a descendant of it.
    try:
        managed_root = managed_root_folder()
    except FolderConfigError as cfg_err:
        raise HTTPException(status_code=503, detail=str(cfg_err))
    if not target_folder:
        target_folder = managed_root
        if not folder_name:
            folder_name = "Workloads Root"
    normalized_target = normalize_folder_name(target_folder)
    if not normalized_target or not is_descendant_of_root(normalized_target):
        raise HTTPException(status_code=400, detail=f"Destination folder must be {managed_root} or one of its sub-folders.")
    target_folder = normalized_target

    if target_folder and not folder_name and db:
        try:
            doc_key = target_folder.replace("folders/", "folders_")
            f_doc = db.collection("managed_folders").document(doc_key).get()
            if f_doc.exists:
                folder_name = f_doc.to_dict().get("display_name")
        except Exception:
            pass

    # FD-4CI-b-R1: a request without a branch gets its branch below, once the stored workload document is known.
    target_branch = req.target_branch or "main"

    # Resolve Sandbox Designation & Lifespan
    is_sandbox = False
    sandbox_ttl_days = 30
    # Interim lane-18 guard: record HOW the workload became a sandbox. Only an explicit designation (the API field /
    # dashboard checkbox) makes it eligible for the automatic TTL delete; keyword detection never does.
    sandbox_designation_source = None
    if req.is_sandbox is True:
        is_sandbox = True
        sandbox_ttl_days = int(req.sandbox_ttl_days or 30)
        sandbox_designation_source = "API_FIELD"
    elif req.is_sandbox is None:
        full_text = f"{req.title or ''} {req.description or ''} {spec_text}"
        detected_sandbox, detected_ttl = detect_sandbox_intent(full_text)
        if detected_sandbox:
            is_sandbox = True
            sandbox_ttl_days = detected_ttl
            sandbox_designation_source = "KEYWORD_DETECTED"

    sandbox_expires_at = compute_sandbox_expiry(sandbox_ttl_days) if is_sandbox else None
    sandbox_decommission_status = "SCHEDULED" if is_sandbox else None

    workload_record = {
        "product_id": clean_pid,
        "project_id": target_project_id,
        "vcs_provider": clean_vcs_provider,
        "github_repo": full_github_repo,
        "default_branch": target_branch,
        "folder_id": target_folder,
        "folder_name": folder_name or target_folder,
        "status": "PROVISIONING",
        "creation_mode": "EXPRESS" if is_express else "AGENT",
        "budget_ceiling_monthly_usd": budget,
        "current_spend_usd": 0.0,
        "projected_monthly_spend_usd": 0.0,
        "spend_last_updated_at": now_iso,
        "is_overrun_projected": False,
        "service_url": "",
        "created_at": now_iso,
        "description": req.description or req.title or f"{'Express' if is_express else 'Autonomous'} workload: {clean_pid}",
        "initialized_by": admin_email,
        "is_castor": False,
        "code_freeze": freeze_on_create,
        "sre_auto_healing_enabled": True,
        "refactor_scanner_enabled": True,
        "require_human_code_review": bool(chosen_require_review),
        "auto_merge": not bool(chosen_require_review),
        "require_plan_approval": bool(chosen_plan_approval),
        "iac_engine": clean_engine,
        # --- FinOps Breach Policy ---
        "budget_breach_policy": (
            req.budget_breach_policy.value if hasattr(req.budget_breach_policy, "value") else str(req.budget_breach_policy)
        ) if req.budget_breach_policy else _platform_default_breach_policy(plat_settings),
        # --- Autonomous Sandbox Lifespan Fields ---
        "is_sandbox": is_sandbox,
        "sandbox_ttl_days": sandbox_ttl_days,
        "sandbox_expires_at": sandbox_expires_at,
        "sandbox_auto_decommission": is_sandbox,
        "sandbox_designation_source": sandbox_designation_source,
        "sandbox_decommission_status": sandbox_decommission_status,
        "cumulative_lifespan_days": sandbox_ttl_days if is_sandbox else 0,
        "extension_count": 0,
        "creator_email": admin_email,
    }

    # compliance-profile-explicit: the explicit selection is stored on the workload (every later run and the apply-time
    # compliance gate read it) and sent with the intake event. Unset = no selection (never inferred from the spec).
    chosen_compliance_profile = req.compliance_profile.value if req.compliance_profile is not None else None
    # Owner decision 10-18 (row CP-9): Express renders no CMEK / audit-logging controls, so a regulated profile is
    # refused here, at create, instead of at apply.
    if is_express and chosen_compliance_profile not in (None, "STANDARD"):
        raise HTTPException(status_code=422, detail={
            "error_class": "EXPRESS_REGULATED_PROFILE_UNSUPPORTED",
            "detail": (f"Express mode does not support the regulated compliance profile {chosen_compliance_profile}; "
                       "use Agent mode or the STANDARD profile."),
        })
    # FD-7M-a (RT F2): with a baseline chosen, the workload's region and its baseline check are settled here, before
    # the compliance downgrade guard below (which may write an approval card), so a refused region writes nothing.
    # Without a baseline there is no check and no card: the region is settled at the record write (no extra read).
    region_decision, region_existing = None, None
    if chosen_compliance_profile is not None:
        region_existing = _stored_workload_doc(clean_pid)
        region_decision = _create_region(clean_pid, region_existing, req.region, default_region, orch_settings)
        _refuse_region_profile_conflict(region_decision[0], chosen_compliance_profile)
    # EXP-6: a re-submit must not rename an event worker OpenTofu may manage (refused here, before any side effect).
    # A first create marks the record as name-plan tracked; an accepted request adds its names in the write below.
    if is_express:
        first_create, names_to_store = _guard_express_worker_renames(clean_pid, req.module_instances or [])
        if first_create:
            workload_record[EXPRESS_NAME_PLAN_TRACKED_FIELD] = True
        if names_to_store is not None:
            workload_record[EXPRESS_DEPLOYED_NAME_PLAN_FIELD] = names_to_store
    if chosen_compliance_profile is not None:
        _guard_compliance_downgrade(clean_pid, chosen_compliance_profile, admin_email, now_iso)
        workload_record["requested_compliance_profile"] = chosen_compliance_profile

    # Lane 19 L19-11: the submitter's access answer, validated by the schema (422 otherwise), is the workload's
    # authoritative access record; the developer reads workloads/{pid}.access itself (the intake event carries no copy,
    # RT F9). Unset = no record (never guessed).
    chosen_access = access_record(req.access.to_policy("intake")) if req.access is not None else None
    default_access_applied = False
    express_record = None   # FD-4CS: the access record an Express create is checked against (below)
    if chosen_access is not None:
        # RT F2: a re-create never changes an existing record silently (no audit entry); that is the admin PATCH's job.
        if db:
            try:
                existing_snap = db.collection("workloads").document(clean_pid).get()
            except Exception as e:  # noqa: BLE001 - cannot tell whether a different record exists: refuse
                raise HTTPException(status_code=503, detail=f"workloads/{clean_pid} unreadable ({type(e).__name__})")
            existing_exists = bool(getattr(existing_snap, "exists", False))
            existing_access = (existing_snap.to_dict() or {}).get("access") if existing_exists else None
            if existing_exists and existing_access is None:
                # L19-F4 RT R1: the first record of an EXISTING workload is a widening (NO_PREVIOUS_RECORD); only the
                # admin PATCH confirms it, audits it and forces plan approval on the next run.
                raise HTTPException(
                    status_code=409,
                    detail=f"Workload '{clean_pid}' already exists without an access record; "
                           f"use PATCH /api/workloads/{clean_pid}/access (administrator, audited, confirm_widening) "
                           "to set it.",
                )
            if existing_access is not None and existing_access != chosen_access:
                raise HTTPException(
                    status_code=409,
                    detail=f"Workload '{clean_pid}' already has a different access record; "
                           f"use PATCH /api/workloads/{clean_pid}/access (administrator, audited) to change it.",
                )
            if not existing_exists:
                # APP-ADMIN-DEFAULT: the verified submitter of a NEW workload (never on a re-create)
                workload_record.update(_verified_submitter_fields(request))
        workload_record["access"] = chosen_access
    elif db:
        # OSS-D23 (owner 10-19/10-20): a NEW workload created without an access answer gets the platform
        # default record (PRIVATE_IAP, Google sign-in through IAP, source "platform_default") listing the verified
        # submitter; with no verified submitter it lists nobody and its build stops with ACCESS_POLICY_INCOMPLETE
        # until an administrator lists who may use it. Never public by omission. An
        # existing workload document is never given one here (no silent migration); public stays an explicit choice.
        # FD-4CS (owner 10-20): Express creates get the same default (its synthesizer applies the record).
        try:
            default_snap = db.collection("workloads").document(clean_pid).get()
        except Exception as e:  # noqa: BLE001 - cannot tell whether the workload is new: refuse
            raise HTTPException(status_code=503, detail=f"workloads/{clean_pid} unreadable ({type(e).__name__})")
        if not getattr(default_snap, "exists", False):
            workload_record.update(_default_access_fields(request))
            default_access_applied = True
        else:
            stored_doc = default_snap.to_dict()
            express_record = stored_doc.get("access") if isinstance(stored_doc, dict) else None
    if chosen_access is not None or default_access_applied:
        express_record = workload_record.get("access")
    if is_express and express_access_arguments is not None and express_record is not None:
        # FD-4CS: a compute-cloudrun parameter that contradicts the record this request writes, or (re-submit without
        # `access`) the record the workload already has, is refused before anything is written (the synthesizer
        # checks it again at build time; an incomplete record waits, as above).
        try:
            express_access_arguments(req.module_instances or [], stored_access_policy(express_record))
        except ExpressSynthesisRefused as refused:   # ACCESS_POLICY_INCOMPLETE is checked after conflicts: it waits
            if refused.reason == "EXPRESS_ACCESS_CONFLICT":
                raise HTTPException(status_code=422, detail={"error_class": refused.reason, "detail": str(refused)})

    initial = {"code_freeze": freeze_on_create, "sre_auto_healing_enabled": True, "refactor_scanner_enabled": True}
    if not default_access_applied:
        # FD-4CU / FD-4CU-b: the document may already exist (a re-create / Express re-submit). Each kept field it
        # already has stays as stored (left out of the merge write below); absent fields get the new-workload value.
        # An unreadable document gets no SRE / scanner write (nothing is turned back on) and only ever a freeze. (With
        # the default access applied the document did not exist and is written with create() semantics: new.)
        stored = _stored_workload_doc(clean_pid)
        if stored is None:
            workload_record.pop("sre_auto_healing_enabled", None)
            workload_record.pop("refactor_scanner_enabled", None)
            if not freeze_on_create:
                workload_record.pop("code_freeze", None)
                initial["code_freeze"] = True   # nothing written: the stored value may be frozen, never claim False
        else:
            for field in KEPT_ON_RECREATE:
                if field in stored:
                    workload_record.pop(field, None)
                    initial[field] = stored.get(field) is True
        # GITHUB-REPO-NAME-NO-PREFIX (RT F3): a re-create of an existing workload that names no repository keeps the
        # repository it has recorded (a workload vended before 11-12 stays on its castor-<id> repository; the default
        # would point vending at a new, empty one). Unreadable document: `github_repo` is not written (whatever is
        # recorded stays; vending reads the record itself and refuses to vend without it).
        if not (req.github_repo and req.github_repo.strip()):
            kept_repo = _stored_repo_name(stored.get("github_repo")) if stored is not None else None
            if stored is None:
                workload_record.pop("github_repo", None)
            elif kept_repo:
                full_github_repo = kept_repo
                workload_record.pop("github_repo", None)
    if not req.target_branch:   # FD-4CI-b-R1 (default access applied: the document did not exist -> new)
        target_branch = _new_workload_branch(clean_pid, {} if default_access_applied else stored,
                                             lambda **_k: plat_settings)
        workload_record["default_branch"] = target_branch
    # GHA-DEPLOY-SWITCH: GitHub workloads only. A new workload stores the request's answer (unset = on); an existing one
    # keeps its stored value (a different answer is refused: the audited PATCH changes it).
    _apply_create_gha_switch(clean_pid, req.github_actions_deploy, clean_vcs_provider, workload_record,
                             {} if default_access_applied else stored)

    # FD-7M-a: the region is recorded once, on a NEW workload (Agent and Express); an existing one keeps its own.
    if region_decision is None:   # no baseline chosen: nothing to check against, settled from the read above
        workload_region_value, write_region = _create_region(
            clean_pid, {} if default_access_applied else stored, req.region, default_region, orch_settings)
    else:
        workload_region_value, write_region = region_decision
        if default_access_applied and region_existing is None:
            write_region = True   # the early read failed, but this create found no document: a new workload
    if write_region:
        workload_record["region"] = workload_region_value

    initial_request_id: Optional[str] = None   # set once its feature request is saved: no store, no id on the event
    if db:
        # RT F5: the default was chosen because the document did not exist; it is written with create() semantics, so
        # a concurrent create (for example an explicit PUBLIC_APP answer) is never overwritten: AlreadyExists -> 409.
        from google.api_core import exceptions as _gexc

        try:
            if default_access_applied:
                try:
                    db.collection("workloads").document(clean_pid).create(workload_record)
                except _gexc.AlreadyExists:
                    raise HTTPException(status_code=409, detail=f"Workload '{clean_pid}' was created concurrently; "
                                                                "retry the request.")
            else:
                db.collection("workloads").document(clean_pid).set(workload_record, merge=True)
            logger.info(f"Registered new workload '{clean_pid}' (Mode: {'EXPRESS' if is_express else 'AGENT'}, VCS: {clean_vcs_provider}, Sandbox: {is_sandbox}) in Firestore by {admin_email}")

            # Persist initial specification in feature_requests collection
            req_id = f"spec-{clean_pid}-{int(time.time())}"
            spec_doc = {
                "request_id": req_id,
                "product_id": clean_pid,
                "project_id": target_project_id,
                "vcs_provider": clean_vcs_provider,
                "github_repo": full_github_repo,
                "creation_mode": "EXPRESS" if is_express else "AGENT",
                "title": req.title or f"Initial {'Express ' if is_express else ''}Build: {clean_pid}",
                "description": spec_text,
                "change_type": "NEW_FEATURE",
                "priority": "HIGH",
                "target_components": "All Services & Infrastructure",
                "acceptance_criteria": "Build and deploy production-ready service according to specification.",
                "status": "IN_PROGRESS",
                "created_at": now_iso,
                "created_by": admin_email,
                "is_sandbox": is_sandbox,
                "sandbox_ttl_days": sandbox_ttl_days,
                "sandbox_expires_at": sandbox_expires_at,
            }
            db.collection("feature_requests").document(req_id).set(spec_doc)
            initial_request_id = req_id
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to persist workload '{clean_pid}' to Firestore: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to save workload to Firestore: {e}")

    # Dispatch: Express Pipeline vs Autonomous Pub/Sub Swarm
    build_queue_view: Optional[Dict[str, Any]] = None   # BUILD-ADMISSION-QUEUE: set when the build waits for a slot
    if is_express:
        express_trace_id = f"express-{clean_pid}-{uuid.uuid4().hex[:6]}"
        module_instances_payload = [
            inst.model_dump() if hasattr(inst, "model_dump") else (inst.dict() if hasattr(inst, "dict") else inst)
            for inst in (req.module_instances or [])
        ]
        if background_tasks:
            background_tasks.add_task(
                execute_express_provisioning,
                product_id=clean_pid,
                target_project_id=target_project_id,
                clean_vcs_provider=clean_vcs_provider,
                full_github_repo=full_github_repo,
                target_branch=target_branch,
                target_folder=target_folder,
                budget=budget,
                clean_engine=clean_engine,
                is_sandbox=is_sandbox,
                admin_email=admin_email,
                module_instances=module_instances_payload,
                include_vpc=bool(req.include_vpc),
                trace_id=express_trace_id,
                sandbox_auto_decommission=is_sandbox,
                sandbox_designation_source=sandbox_designation_source,
                sandbox_ttl_days=sandbox_ttl_days,
                approved_removals=list(req.approved_removals or []),
                region=workload_region_value,   # FD-7M-a: the region this create resolved and recorded
            )
            logger.info(f"Dispatched Express provisioning to background worker for '{clean_pid}' (Trace: {express_trace_id})")
        else:
            execute_express_provisioning(
                product_id=clean_pid,
                target_project_id=target_project_id,
                clean_vcs_provider=clean_vcs_provider,
                full_github_repo=full_github_repo,
                target_branch=target_branch,
                target_folder=target_folder,
                budget=budget,
                clean_engine=clean_engine,
                is_sandbox=is_sandbox,
                admin_email=admin_email,
                module_instances=module_instances_payload,
                include_vpc=bool(req.include_vpc),
                trace_id=express_trace_id,
                sandbox_auto_decommission=is_sandbox,
                sandbox_designation_source=sandbox_designation_source,
                sandbox_ttl_days=sandbox_ttl_days,
                approved_removals=list(req.approved_removals or []),
                region=workload_region_value,   # FD-7M-a: the region this create resolved and recorded
            )
    else:
        # Dispatch to spec_intake_events Pub/Sub topic. RT14-19: a build event that cannot be sent (no publisher,
        # publish error, timeout) is a typed error (503 / 502 / 504) with the workload marked, never a 200 PROVISIONING
        # with nothing behind it.
        pub_client = get_pubsub_publisher()
        intake_trace_id = f"intake-{clean_pid}-{uuid.uuid4().hex[:6]}"
        try:
            intake_payload = {
                "trace_id": intake_trace_id,
                "product_id": clean_pid,
                "project_id": target_project_id,
                "vcs_provider": clean_vcs_provider,
                "github_repo": full_github_repo,
                "default_branch": target_branch,
                # FD-4CI-b-R1: the workflow deploys `target_branch` (absent it defaults to main).
                "target_branch": target_branch,
                "folder_id": target_folder,
                "title": req.title or f"Initial Build: {clean_pid}",
                "spec_text": spec_text,
                "source_channel": "control_center_form",
                "created_at": now_iso,
                "budget_ceiling_monthly_usd": budget,
                "require_human_code_review": bool(chosen_require_review),
                "auto_merge": not bool(chosen_require_review),
                "require_plan_approval": bool(chosen_plan_approval),
                "iac_engine": clean_engine,
                "is_sandbox": is_sandbox,
                "sandbox_ttl_days": sandbox_ttl_days,
                "sandbox_expires_at": sandbox_expires_at,
            }
            # Lane 18 S2: the workflow's vend call forwards the explicit designation vending records at birth
            # (workflows/main_orchestrator.yaml dispatch_vending_task), in vending's vocabulary.
            vend_fields = destructive_actions.vend_sandbox_fields(
                is_sandbox=is_sandbox, auto_decommission=is_sandbox,
                designation_source=sandbox_designation_source, ttl_days=sandbox_ttl_days)
            intake_payload["sandbox_auto_decommission"] = vend_fields["sandbox_auto_decommission"]
            intake_payload["sandbox_designation_source"] = vend_fields["sandbox_designation_source"]
            if chosen_compliance_profile is not None:
                intake_payload["compliance_profile"] = chosen_compliance_profile
            # RESUME-DEVELOPER-TASK-DAG: the gateway records it on the run, so a later Resume of another feature
            # request is refused (`_resume_developer_block`). Run metadata only: the workflow never reads it.
            if initial_request_id:
                intake_payload["request_id"] = initial_request_id
            # BUILD-ADMISSION-QUEUE (G4): the build takes a slot before anything is published; over the limit it
            # waits in the queue (202, nothing published) and is published when a running build ends.
            build_queue_view = _dispatch_first_build(
                product_id=clean_pid, pub_client=pub_client, current_project=current_project,
                intake_payload=intake_payload, source="control_center_form",
                title=req.title or f"Initial Build: {clean_pid}", request_id=initial_request_id, now_iso=now_iso,
                response=response)
        except HTTPException:
            raise   # typed: admission refusal (503 / 409) or RT14-19 dispatch outcome (503 / 502 / 504)
        except Exception as e:  # noqa: BLE001 - building the event failed: nothing was published
            detail = f"build event not built ({type(e).__name__}: {e}); no workflow was started"
            logger.error(f"{INTAKE_DISPATCH_FAILED}: '{clean_pid}': {detail}")
            if db is not None:
                _release_unpublished_build(intake_trace_id)
            _fail_new_workload_dispatch(clean_pid, initial_request_id, INTAKE_DISPATCH_FAILED, detail)
            raise HTTPException(status_code=502, detail={
                "code": INTAKE_DISPATCH_FAILED, "error_class": INTAKE_DISPATCH_FAILED, "trace_id": intake_trace_id,
                "product_id": clean_pid, "message": f"Workload registered but build dispatch failed: {detail}."})

    return WorkloadSummary(
        product_id=clean_pid,
        project_id=target_project_id,
        vcs_provider=clean_vcs_provider,
        github_repo=full_github_repo,
        default_branch=target_branch,
        folder_id=target_folder,
        folder_name=folder_name,
        status="PROVISIONING",
        budget_ceiling_monthly_usd=budget,
        current_spend_usd=0.0,
        projected_monthly_spend_usd=0.0,
        spend_last_updated_at=now_iso,
        is_overrun_projected=False,
        service_url="",
        created_at=now_iso,
        is_castor=False,
        code_freeze=initial["code_freeze"],
        sre_auto_healing_enabled=initial["sre_auto_healing_enabled"],
        refactor_scanner_enabled=initial["refactor_scanner_enabled"],
        require_human_code_review=bool(chosen_require_review),
        auto_merge=not bool(chosen_require_review),
        require_plan_approval=bool(chosen_plan_approval),
        iac_engine=clean_engine,
        # COMPLIANCE-BASELINE-LABEL (display only): from the stored selection; no folder decision exists yet.
        **compliance_label({"requested_compliance_profile": chosen_compliance_profile}),
        build_queue=build_queue_view,
    )



@router.post("/api/workloads/bootstrap-castor", response_model=WorkloadSummary, dependencies=[require(ADMIN)])
def bootstrap_castor_workload(request: Request):
    verify_admin_access(request)
    """
    Initializes StackVend as the primary platform workload in Firestore
    when loading the system for the first time.
    """
    user_role = getattr(request.state, "user_role", UserRole.APPROVER)
    admin_email = getattr(request.state, "user_email", "admin-console")

    current_project = project_id or os.getenv("PROJECT_ID", "")
    if not current_project:
        raise HTTPException(status_code=503, detail="PROJECT_ID is not configured on this Control Center.")
    now_iso = datetime.now(timezone.utc).isoformat()

    # FD-4AY: the platform repository comes only from GITHUB_REPO ("owner/repo", or "repo" + GITHUB_OWNER).
    # No guessed default; unset => 503 with a clear message.
    github_repo_name = (os.getenv("GITHUB_REPO") or "").strip()
    if not github_repo_name:
        raise HTTPException(status_code=503, detail="GITHUB_REPO is not configured; set it (owner/repo) to register the platform workload.")
    full_github_repo = github_repo_name if "/" in github_repo_name else f"{require_github_owner()}/{github_repo_name}"
    try:
        _service_urls = identity.get_runtime_identity().service_urls
    except Exception:  # noqa: BLE001
        _service_urls = ()

    castor_record = {
        "product_id": "project-castor",
        "project_id": current_project,
        "github_repo": full_github_repo,
        "default_branch": "main",
        "status": "ACTIVE",
        "budget_ceiling_monthly_usd": 100.0,
        "current_spend_usd": 0.0,
        "projected_monthly_spend_usd": 0.0,
        "spend_last_updated_at": now_iso,
        "is_overrun_projected": False,
        "service_url": _service_urls[0] if _service_urls else "",
        "created_at": now_iso,
        "description": "StackVend Platform Engine (Immutable Platform)",
        "initialized_by": admin_email,
        "is_castor": True,
        "code_freeze": True,
        "sre_auto_healing_enabled": False,
        "refactor_scanner_enabled": False,
        "iac_engine": "TERRAFORM",
    }

    if db:
        try:
            db.collection("workloads").document("project-castor").set(castor_record, merge=True)
            logger.info(f"Initialized StackVend platform workload with GitHub repo '{full_github_repo}' in Firestore by {admin_email}")
        except Exception as e:
            logger.error(f"Failed to initialize StackVend platform workload in Firestore: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to write to Firestore: {e}")

    return WorkloadSummary(
        product_id="project-castor",
        project_id=current_project,
        github_repo=full_github_repo,
        default_branch="main",
        status="ACTIVE",
        budget_ceiling_monthly_usd=100.0,
        current_spend_usd=0.0,
        projected_monthly_spend_usd=0.0,
        spend_last_updated_at=now_iso,
        is_overrun_projected=False,
        service_url=castor_record["service_url"],
        created_at=now_iso,
        is_castor=True,
        code_freeze=castor_record["code_freeze"],
        sre_auto_healing_enabled=castor_record["sre_auto_healing_enabled"],
        refactor_scanner_enabled=castor_record["refactor_scanner_enabled"],
        iac_engine="TERRAFORM",
    )


def _iac_intent_warnings(workload_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """TI-3i: the developer's `iac_intent_warnings` (typed-intent entries a repair removed), list of objects only."""
    raw = workload_data.get("iac_intent_warnings")
    return [w for w in raw if isinstance(w, dict)][:20] if isinstance(raw, list) else []


RUNTIME_ENV_ADVISORIES_SHOWN = 50


def _runtime_env_advisories(workload_data: Dict[str, Any]) -> Dict[str, Any]:
    """RUNTIME-ENV-CONTRACT-CHECK: the developer's `runtime_env_advisories` (objects only, at most 50) and their total
    (at least the number kept; a malformed total counts the kept entries)."""
    raw = workload_data.get("runtime_env_advisories")
    items = [a for a in raw if isinstance(a, dict)][:RUNTIME_ENV_ADVISORIES_SHOWN] if isinstance(raw, list) else []
    total = workload_data.get("runtime_env_advisories_total")
    if isinstance(total, bool) or not isinstance(total, int) or total < len(items):
        total = len(items)
    return {"runtime_env_advisories": items, "runtime_env_advisories_total": total}


@router.get("/api/workloads/{product_id}/details", response_model=WorkloadDetailsResponse, dependencies=[require(WORKLOAD())])
def get_workload_details(product_id: str, request: Request):
    verify_workload_access(product_id, request)
    """
    Retrieves comprehensive workload metadata and all deployed assets from the Terraform state.
    """
    workload_data = {}
    if db:
        try:
            doc = db.collection("workloads").document(product_id).get()
            if doc.exists:
                workload_data = doc.to_dict() or {}
        except Exception as e:
            logger.warning(f"Could not fetch workload doc for {product_id}: {e}")

    proj_id = workload_data.get("project_id") or project_id
    gh_repo = _stored_repo_name(workload_data.get("github_repo"))
    raw_vcs = workload_data.get("vcs_provider")
    if not raw_vcs:
        if gh_repo and "serverless-git" in str(gh_repo).lower():
            raw_vcs = "SERVERLESS_GIT"
        else:
            raw_vcs = "GITHUB"
    clean_vcs_provider = str(raw_vcs).strip().upper()

    git_clone_url = None
    git_clone_url_error = None
    resolved_repo = gh_repo
    clean_pid = product_id.lower().replace("_", "-")
    if clean_vcs_provider == "SERVERLESS_GIT":
        # FALLBACK-URLS (fail-loudly 1.4): the real git server URL (env / platform setting / Cloud Run Admin API) or
        # no clone URL plus the typed GIT_SERVER_URL_UNKNOWN; never one built from the project id and a fixed region.
        git_server_url = get_git_server_url()
        if git_server_url:
            git_clone_url = f"{git_server_url}/git/{clean_pid}.git"
        else:
            git_clone_url_error = GIT_SERVER_URL_UNKNOWN
            logger.warning(f"No clone URL for '{product_id}': the Serverless Git server URL is unknown "
                           f"(GIT_SERVER_URL unset, no governance.git_server_url, Cloud Run lookup found none)")
    else:
        _, _, full_repo = resolve_repo_identity(gh_repo, product_id=product_id)
        git_clone_url = f"https://github.com/{full_repo}.git"
        resolved_repo = full_repo  # FD-4AY (RT F2): GitHub links use the owner-resolved name, not '#'

    def_branch = workload_data.get("default_branch", "main")
    status = workload_data.get("status", "ACTIVE")
    budget = float(workload_data.get("budget_ceiling_monthly_usd", 100.0 if product_id == "project-castor" else 40.0))
    spend = float(workload_data.get("current_spend_usd", 0.0))
    proj_spend = float(workload_data.get("projected_monthly_spend_usd", calculate_run_rate_projection(spend)))
    spend_updated = workload_data.get("spend_last_updated_at")
    is_overrun = bool(workload_data.get("is_overrun_projected", proj_spend > budget))
    service_url = workload_data.get("service_url")
    created_at = workload_data.get("created_at")
    description = workload_data.get("description")
    is_castor_val = bool(workload_data.get("is_castor", product_id in ["project-castor", "castor", "platform"]))
    code_freeze_val = bool(workload_data.get("code_freeze", False))
    sre_auto_healing_val = bool(workload_data.get("sre_auto_healing_enabled", True))
    refactor_scanner_val = bool(workload_data.get("refactor_scanner_enabled", True))
    if workload_data.get("auto_merge") is True:
        require_human_code_review_val = False
        auto_merge_val = True
    elif "require_human_code_review" in workload_data:
        require_human_code_review_val = bool(workload_data.get("require_human_code_review"))
        auto_merge_val = not require_human_code_review_val
    else:
        require_human_code_review_val = True
        auto_merge_val = False
    require_plan_approval_val = bool(workload_data.get("require_plan_approval", False))

    # 1. Attempt to fetch state from GCS
    state_info = fetch_workload_state_from_gcs(product_id, proj_id)

    # 2. Check if Firestore recorded a deployment
    if not state_info and db:
        try:
            dep_docs = db.collection("terraform_deployments").where("product_id", "==", product_id).limit(1).stream()
            for d in dep_docs:
                dep_data = d.to_dict() or {}
                if "outputs" in dep_data:
                    state_info = {
                        "terraform_version": "1.5+",
                        "serial": 1,
                        "state_source": f"Firestore Audit Record ({d.id})",
                        "resources_count": len(dep_data.get("outputs", {})),
                        "resources": [],
                        "outputs": _masked_record_outputs(dep_data.get("outputs", {})),   # RT14-09
                    }
        except Exception:
            pass

    # 3. Platform fallback for project-castor if state file not yet uploaded to GCS
    if not state_info and product_id in ["project-castor", "castor", "platform"]:
        state_info = get_platform_default_deployed_assets(proj_id)

    if not state_info:
        state_info = {
            "terraform_version": None,
            "serial": None,
            "state_source": f"gs://castor-tfstate-{proj_id}/workloads/{product_id}/default.tfstate (Pending Provisioning)",
            "resources_count": 0,
            "resources": [],
            "outputs": {},
        }

    # RT14-03: OpenTofu outputs can carry values a VIEWER may not read (connection strings, generated credentials that
    # an older deploy record holds unmasked). Only managers and administrators get them; a VIEWER sees why.
    outputs_val = state_info.get("outputs", {}) or {}
    outputs_withheld_reason = None
    if outputs_val and not _may_read_outputs(request):
        outputs_val, outputs_withheld_reason = {}, OUTPUTS_MANAGER_ONLY

    network_meta = workload_data.get("network")
    if not network_meta and db:
        try:
            alloc_docs = db.collection("cidr_allocations").where("product_id", "==", product_id).stream()
            for ad in alloc_docs:
                adata = ad.to_dict() or {}
                if adata.get("purpose") == "SERVERLESS_VPC_CONNECTOR":
                    network_meta = network_meta or {}
                    network_meta["connector_cidr"] = adata.get("cidr_block")
                    network_meta["vpc_name"] = adata.get("network_name")
                    network_meta["status"] = adata.get("status")
        except Exception:
            pass

    return WorkloadDetailsResponse(
        product_id=product_id,
        project_id=proj_id,
        github_repo=resolved_repo,
        vcs_provider=clean_vcs_provider,
        git_clone_url=git_clone_url,
        git_clone_url_error=git_clone_url_error,
        default_branch=def_branch,
        status=status,
        budget_ceiling_monthly_usd=budget,
        current_spend_usd=spend,
        projected_monthly_spend_usd=proj_spend,
        spend_last_updated_at=spend_updated,
        is_overrun_projected=is_overrun,
        spend_source=workload_data.get("spend_source"),
        cached_hourly_burn_usd=workload_data.get("cached_hourly_burn_usd"),
        service_url=service_url,
        service_url_unknown_reason=workload_data.get("service_url_unknown_reason"),
        created_at=created_at,
        description=description,
        state_source=state_info.get("state_source"),
        terraform_version=state_info.get("terraform_version"),
        serial=state_info.get("serial"),
        resources_count=state_info.get("resources_count", 0),
        resources=state_info.get("resources", []),
        outputs=outputs_val,
        outputs_withheld_reason=outputs_withheld_reason,
        is_castor=is_castor_val,
        code_freeze=code_freeze_val,
        github_actions_deploy=_gha_deploy_switch(workload_data, clean_vcs_provider),   # GHA-DEPLOY-SWITCH
        sre_auto_healing_enabled=sre_auto_healing_val,
        refactor_scanner_enabled=refactor_scanner_val,
        require_human_code_review=require_human_code_review_val,
        auto_merge=auto_merge_val,
        require_plan_approval=require_plan_approval_val,
        budget_breach_policy=workload_data.get("budget_breach_policy", "AUTONOMOUS_SCALE_TO_ZERO"),
        buffer_ceiling_usd=workload_data.get("buffer_ceiling_usd"),
        iac_engine=workload_data.get("iac_engine", "TERRAFORM"),
        region=_recorded_region(workload_data),   # FD-7M-a
        decommissioned_at=workload_data.get("decommissioned_at"),
        decommissioned_by=workload_data.get("decommissioned_by"),
        archived_at=workload_data.get("archived_at"),
        archived_by=workload_data.get("archived_by"),
        last_active_project_id=workload_data.get("last_active_project_id"),
        last_iac_upgrade_at=workload_data.get("last_iac_upgrade_at"),
        last_iac_upgrade_by=workload_data.get("last_iac_upgrade_by"),
        last_iac_upgrade_status=workload_data.get("last_iac_upgrade_status"),
        network=network_meta,
        file_attribution=workload_data.get("file_attribution", {}),
        iac_intent_warnings=_iac_intent_warnings(workload_data),   # TI-3i
        **_runtime_env_advisories(workload_data),   # RUNTIME-ENV-CONTRACT-CHECK
        is_sandbox=bool(workload_data.get("is_sandbox", False)),
        sandbox_ttl_days=workload_data.get("sandbox_ttl_days", 30),
        sandbox_expires_at=workload_data.get("sandbox_expires_at"),
        sandbox_days_remaining=compute_days_remaining(workload_data.get("sandbox_expires_at")) if workload_data.get("is_sandbox") else None,
        sandbox_auto_decommission=bool(workload_data.get("sandbox_auto_decommission", workload_data.get("is_sandbox", False))),
        **destructive_actions.sandbox_display_fields(workload_data),
        sandbox_decommission_status="EXPIRATION_IMMINENT" if (workload_data.get("is_sandbox") and compute_days_remaining(workload_data.get("sandbox_expires_at")) is not None and compute_days_remaining(workload_data.get("sandbox_expires_at")) <= 3.0 and status != "DECOMMISSIONED" and workload_data.get("sandbox_decommission_status") not in SWEEP_OUTCOME_STATUSES) else workload_data.get("sandbox_decommission_status"),
        cumulative_lifespan_days=int(workload_data.get("cumulative_lifespan_days", workload_data.get("sandbox_ttl_days", 30) if workload_data.get("is_sandbox") else 0)),
        extension_count=int(workload_data.get("extension_count", 0)),
        max_extensions_allowed=3,
        max_cumulative_days_allowed=90,
        creator_email=workload_data.get("creator_email") or workload_data.get("initialized_by"),
        **compliance_label(workload_data),   # COMPLIANCE-BASELINE-LABEL (display only)
    )


# ------------------------------------------------------------------------------
# Feature Request Intake & Lifecycle APIs
# ------------------------------------------------------------------------------
@router.post("/api/workloads/{product_id}/feature-requests", response_model=FeatureRequestRecord, dependencies=[require(WORKLOAD(manager=True))])
def submit_feature_request(product_id: str, req: CreateFeatureRequest, request: Request):
    verify_workload_access(product_id, request, require_manager=True)
    """
    Submits a new feature specification or enhancement request for a workload.
    Persists all fields directly to the Firestore 'feature_requests' collection.
    """
    user_email = getattr(request.state, "user_email", "admin-console")
    current_time_str = datetime.now(timezone.utc).isoformat()

    # Determine Project ID and GitHub Repo from Firestore or Environment
    proj_id = project_id or os.getenv("PROJECT_ID", "")
    gh_repo = None
    w_dict = {}
    if db:
        try:
            w_doc = db.collection("workloads").document(product_id).get()
            if w_doc.exists:
                w_dict = w_doc.to_dict() or {}
                proj_id = w_dict.get("project_id", proj_id)
                gh_repo = _stored_repo_name(w_dict.get("github_repo")) or gh_repo
                if w_dict.get("status") in ["QUARANTINED", "BILLING_UNLINKED"]:
                    raise HTTPException(
                        status_code=423,
                        detail=f"Workload '{product_id}' is locked in {w_dict.get('status')} due to a budget breach. Resolve pending HITL budget remediation before submitting requests.",
                    )
        except Exception as e:
            if hasattr(e, "status_code"):
                raise
            logger.warning(f"Could not retrieve workload doc for {product_id}: {e}")

    # Generate deterministic, sortable request ID
    timestamp_key = int(time.time())
    request_id = f"feat-{product_id}-{timestamp_key}"

    # Precompute deterministic plan filename and GitHub URL
    created_date = current_time_str[:10]
    title_clean = req.title.strip().lower()
    slug = re.sub(r'[^a-z0-9]+', '-', title_clean).strip('-')[:40] or "feature"
    clean_pid = product_id.lower().replace("_", "-")
    plan_fn = f"{created_date}-feat-{slug}.md"
    plan_fp = f"docs/planning/{plan_fn}"
    _, _, target_repo = resolve_repo_identity(gh_repo, product_id=product_id)
    vcs_provider = w_dict.get("vcs_provider") or ("SERVERLESS_GIT" if (gh_repo and "serverless-git" in str(gh_repo).lower()) else "GITHUB")
    if vcs_provider == "SERVERLESS_GIT":
        plan_gh_url = f"/api/workloads/{product_id}/plans/{plan_fn}/raw"
    else:
        plan_gh_url = f"https://github.com/{target_repo}/blob/main/{plan_fp}"

    feature_doc = {
        "request_id": request_id,
        "product_id": product_id,
        "project_id": proj_id,
        "github_repo": target_repo,
        "vcs_provider": vcs_provider,
        "title": req.title.strip(),
        "description": req.description.strip(),
        "change_type": req.change_type.value if hasattr(req.change_type, "value") else str(req.change_type),
        "priority": req.priority.value if hasattr(req.priority, "value") else str(req.priority),
        "target_components": req.target_components.strip() if req.target_components else "All Components",
        "acceptance_criteria": req.acceptance_criteria.strip() if req.acceptance_criteria else "",
        "status": "PENDING_TRIAGE",
        "submitted_by": user_email,
        "created_at": current_time_str,
        "channel": "CONTROL_CENTER_UI",
        "plan_filename": plan_fn,
        "plan_file_path": plan_fp,
        "plan_github_url": plan_gh_url,
    }

    if db:
        try:
            db.collection("feature_requests").document(request_id).set(feature_doc)
            logger.info(f"Persisted feature request '{request_id}' to Firestore collection 'feature_requests' for {product_id} by {user_email}")
        except Exception as e:
            logger.error(f"Failed to persist feature request to Firestore: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to save feature request to Firestore: {e}")

    return FeatureRequestRecord(
        request_id=request_id,
        product_id=product_id,
        project_id=proj_id,
        title=feature_doc["title"],
        description=feature_doc["description"],
        change_type=req.change_type,
        priority=req.priority,
        target_components=feature_doc["target_components"],
        acceptance_criteria=feature_doc["acceptance_criteria"],
        status=feature_doc["status"],
        submitted_by=user_email,
        created_at=current_time_str,
        channel="CONTROL_CENTER_UI",
        plan_filename=plan_fn,
        plan_file_path=plan_fp,
        plan_github_url=plan_gh_url,
    )


@router.get("/api/workloads/{product_id}/feature-requests", response_model=List[FeatureRequestRecord], dependencies=[require(WORKLOAD())])
def list_feature_requests(product_id: str, request: Request):
    verify_workload_access(product_id, request)
    """
    Retrieves all feature requests submitted for a specific workload from Firestore.
    """
    results = []
    default_repo_cache: List[Optional[str]] = []   # read once, only for a feature request without its own repository

    def default_repo() -> Optional[str]:
        if not default_repo_cache:
            default_repo_cache.append(_workload_repo_for_feature_request(product_id))
        return default_repo_cache[0]

    if db:
        try:
            # Preload plans for this workload to correlate feature requests to their plan files
            plans_by_trace = {}
            plans_by_name = {}
            try:
                ip_docs = (
                    db.collection("workloads")
                    .document(product_id)
                    .collection("implementation_plans")
                    .stream()
                )
                for ip in ip_docs:
                    ip_data = ip.to_dict() or {}
                    fn = ip_data.get("plan_filename", ip.id)
                    plans_by_name[fn] = ip_data
                    if ip_data.get("trace_id"):
                        plans_by_trace[ip_data["trace_id"]] = ip_data
            except Exception as pe:
                logger.debug(f"Could not preload implementation plans for correlation: {pe}")

            docs = (
                db.collection("feature_requests")
                .where("product_id", "==", product_id)
                .stream()
            )
            for d in docs:
                data = d.to_dict() or {}
                try:
                    c_type = FeatureChangeType(data.get("change_type", "FEATURE_ENHANCEMENT"))
                except ValueError:
                    c_type = FeatureChangeType.FEATURE_ENHANCEMENT

                try:
                    prio = FeatureRequestPriority(data.get("priority", "MEDIUM"))
                except ValueError:
                    prio = FeatureRequestPriority.MEDIUM

                doc_url = data.get("doc_url")
                spec_doc_id = data.get("spec_doc_id") or data.get("file_id") or data.get("google_doc_id")
                if not doc_url and spec_doc_id:
                    doc_url = f"https://docs.google.com/document/d/{spec_doc_id}/edit"
                impl_plan = data.get("implementation_plan") or data.get("plan_markdown") or data.get("technical_plan")
                src_channel = data.get("source_channel") or data.get("channel", "CONTROL_CENTER_UI")
                task_dag = data.get("task_dag")

                # Correlate implementation plan
                req_id = data.get("request_id", d.id)
                trace_id = data.get("trace_id")
                matched_plan = None
                if trace_id and trace_id in plans_by_trace:
                    matched_plan = plans_by_trace[trace_id]
                elif data.get("plan_filename") and data.get("plan_filename") in plans_by_name:
                    matched_plan = plans_by_name[data["plan_filename"]]

                # Match by title or slug if not matched by trace_id / plan_filename
                if not matched_plan and plans_by_name:
                    title_lower = data.get("title", "").lower()
                    title_slug = re.sub(r'[^a-z0-9]+', '-', title_lower).strip('-')[:30]
                    for fn, p_data in plans_by_name.items():
                        fn_lower = fn.lower()
                        if title_slug and title_slug in fn_lower:
                            matched_plan = p_data
                            break
                        title_words = [w for w in title_lower.split() if len(w) > 3]
                        if title_words and any(w in fn_lower for w in title_words):
                            matched_plan = p_data
                            break

                plan_fn = data.get("plan_filename") or (matched_plan.get("plan_filename") if matched_plan else None)
                plan_fp = data.get("plan_file_path") or (matched_plan.get("plan_file_path") if matched_plan else None)
                if not plan_fn:
                    created_date = (data.get("created_at") or "")[:10] or datetime.now(timezone.utc).strftime("%Y-%m-%d")
                    title_clean = data.get("title", "feature").lower()
                    slug = re.sub(r'[^a-z0-9]+', '-', title_clean).strip('-')[:40] or "feature"
                    plan_fn = f"{created_date}-feat-{slug}.md"
                    plan_fp = f"docs/planning/{plan_fn}"
                elif not plan_fp:
                    plan_fp = f"docs/planning/{plan_fn}"

                repo = _stored_repo_name(data.get("github_repo")) or default_repo()
                is_serverless = (data.get("vcs_provider") == "SERVERLESS_GIT") or (repo and "serverless-git" in str(repo).lower())
                if is_serverless:
                    plan_gh_url = data.get("plan_github_url") or f"/api/workloads/{product_id}/plans/{plan_fn}/raw"
                else:
                    plan_gh_url = data.get("plan_github_url") or f"https://github.com/{repo}/blob/main/{plan_fp}"

                results.append(
                    FeatureRequestRecord(
                        request_id=req_id,
                        product_id=data.get("product_id", product_id),
                        project_id=data.get("project_id", ""),
                        title=data.get("title", "Untitled Request"),
                        description=data.get("description", ""),
                        change_type=c_type,
                        priority=prio,
                        target_components=data.get("target_components", "All Components"),
                        acceptance_criteria=data.get("acceptance_criteria", ""),
                        status=data.get("status", "PENDING_TRIAGE"),
                        submitted_by=data.get("submitted_by", "unknown"),
                        created_at=data.get("created_at", ""),
                        channel=data.get("channel", "CONTROL_CENTER_UI"),
                        doc_url=doc_url,
                        spec_doc_id=spec_doc_id,
                        implementation_plan=impl_plan or (matched_plan.get("markdown") if matched_plan else None),
                        source_channel=src_channel,
                        task_dag=task_dag,
                        plan_filename=plan_fn,
                        plan_file_path=plan_fp,
                        plan_github_url=plan_gh_url,
                    )
                )
            results.sort(key=lambda x: x.created_at, reverse=True)
            return results
        except Exception as e:
            logger.warning(f"Error querying feature requests from Firestore ({e}): returning empty list.")

    return []


@router.get("/api/workloads/{product_id}/feature-requests/{request_id}", response_model=FeatureRequestRecord, dependencies=[require(WORKLOAD_CHILD("request_id", "feature_requests", child_field="request_id"))])
def get_feature_request_detail(product_id: str, request_id: str, request: Request):
    verify_workload_access(product_id, request)
    """
    Retrieves the full detail of a specific feature request from Firestore.
    """
    if db:
        try:
            doc = db.collection("feature_requests").document(request_id).get()
            if not doc.exists:
                docs = (
                    db.collection("feature_requests")
                    .where("product_id", "==", product_id)
                    .where("request_id", "==", request_id)
                    .limit(1)
                    .stream()
                )
                for d in docs:
                    doc = d
                    break
            if doc and doc.exists:
                data = doc.to_dict() or {}
                # FD-4N (red-team B1): a feature request is readable only under the workload it belongs to.
                if data.get("product_id") != product_id:
                    raise HTTPException(status_code=404, detail="Feature request not found")
                try:
                    c_type = FeatureChangeType(data.get("change_type", "FEATURE_ENHANCEMENT"))
                except ValueError:
                    c_type = FeatureChangeType.FEATURE_ENHANCEMENT

                try:
                    prio = FeatureRequestPriority(data.get("priority", "MEDIUM"))
                except ValueError:
                    prio = FeatureRequestPriority.MEDIUM

                doc_url = data.get("doc_url")
                spec_doc_id = data.get("spec_doc_id") or data.get("file_id") or data.get("google_doc_id")
                if not doc_url and spec_doc_id:
                    doc_url = f"https://docs.google.com/document/d/{spec_doc_id}/edit"
                impl_plan = data.get("implementation_plan") or data.get("plan_markdown") or data.get("technical_plan")
                src_channel = data.get("source_channel") or data.get("channel", "CONTROL_CENTER_UI")
                task_dag = data.get("task_dag")

                plan_fn = data.get("plan_filename")
                plan_fp = data.get("plan_file_path")
                repo = _stored_repo_name(data.get("github_repo")) or _workload_repo_for_feature_request(product_id)

                if not plan_fn:
                    created_date = (data.get("created_at") or "")[:10] or datetime.now(timezone.utc).strftime("%Y-%m-%d")
                    title_clean = data.get("title", "feature").lower()
                    slug = re.sub(r'[^a-z0-9]+', '-', title_clean).strip('-')[:40] or "feature"
                    plan_fn = f"{created_date}-feat-{slug}.md"
                    plan_fp = f"docs/planning/{plan_fn}"
                elif not plan_fp:
                    plan_fp = f"docs/planning/{plan_fn}"

                is_serverless = (data.get("vcs_provider") == "SERVERLESS_GIT") or (repo and "serverless-git" in str(repo).lower())
                if is_serverless:
                    plan_gh_url = data.get("plan_github_url") or f"/api/workloads/{product_id}/plans/{plan_fn}/raw"
                else:
                    plan_gh_url = data.get("plan_github_url") or f"https://github.com/{repo}/blob/main/{plan_fp}"

                return FeatureRequestRecord(
                    request_id=data.get("request_id", doc.id),
                    product_id=data.get("product_id", product_id),
                    project_id=data.get("project_id", ""),
                    title=data.get("title", "Untitled Request"),
                    description=data.get("description", ""),
                    change_type=c_type,
                    priority=prio,
                    target_components=data.get("target_components", "All Components"),
                    acceptance_criteria=data.get("acceptance_criteria", ""),
                    status=data.get("status", "PENDING_TRIAGE"),
                    submitted_by=data.get("submitted_by", "unknown"),
                    created_at=data.get("created_at", ""),
                    channel=data.get("channel", "CONTROL_CENTER_UI"),
                    doc_url=doc_url,
                    spec_doc_id=spec_doc_id,
                    implementation_plan=impl_plan,
                    source_channel=src_channel,
                    task_dag=task_dag,
                    plan_filename=plan_fn,
                    plan_file_path=plan_fp,
                    plan_github_url=plan_gh_url,
                )
        except Exception as e:
            if hasattr(e, "status_code"):
                raise
            logger.warning(f"Error retrieving feature request detail '{request_id}' ({e})")
            raise HTTPException(status_code=500, detail=str(e))

    raise HTTPException(status_code=404, detail="Feature request not found")


@router.get("/api/workloads/{product_id}/build-plans", response_model=WorkloadBuildPlansResponse, dependencies=[require(WORKLOAD())])
def get_workload_build_plans(product_id: str, request: Request):
    verify_workload_access(product_id, request)
    """Retrieves all historical and active DAG build plans for a workload from Firestore."""
    plans = []
    if db:
        try:
            docs = (
                db.collection("workloads")
                .document(product_id)
                .collection("build_plans")
                .order_by("created_at", direction=firestore.Query.DESCENDING)
                .limit(20)
                .stream()
            )
            for d in docs:
                data = d.to_dict() or {}
                plans.append(BuildPlanResponse(**data))
        except Exception as e:
            logger.warning(f"Could not read build plans from subcollection for {product_id}: {e}")
            try:
                docs = (
                    db.collection("build_plans")
                    .where("product_id", "==", product_id)
                    .stream()
                )
                for d in docs:
                    data = d.to_dict() or {}
                    plans.append(BuildPlanResponse(**data))
            except Exception as fallback_e:
                logger.warning(f"Fallback build plan query failed: {fallback_e}")

    return WorkloadBuildPlansResponse(
        product_id=product_id,
        total_count=len(plans),
        build_plans=plans,
    )


@router.get("/api/build-plans/{trace_id}", response_model=BuildPlanResponse, dependencies=[require(TRACE(collection="build_plans"))])
def get_build_plan_by_trace(trace_id: str, request: Request = None):
    """Retrieves a specific build plan by workflow trace ID."""
    if db:
        try:
            doc = db.collection("build_plans").document(trace_id).get()
            if doc.exists:
                data = doc.to_dict() or {}
                if request:
                    pid = data.get("product_id")
                    if pid:
                        verify_workload_access(pid, request)
                return BuildPlanResponse(**data)
        except Exception as e:
            logger.warning(f"Failed to fetch build plan {trace_id}: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    raise HTTPException(status_code=404, detail="Build plan not found")


@router.get("/api/workloads/{product_id}/plans", response_model=WorkloadPlansResponse, dependencies=[require(WORKLOAD())])
def get_workload_implementation_plans(product_id: str, request: Request):
    verify_workload_access(product_id, request)
    """Retrieves all 7-section Architecture Implementation Plans from docs/planning/ for a workload."""
    plans = []
    clean_pid = product_id.lower().replace("_", "-")
    stored_repo = None
    _, _, full_repo = resolve_repo_identity(None, product_id=product_id)
    vcs_provider = "GITHUB"

    if db:
        try:
            wl_doc = db.collection("workloads").document(product_id).get()
            if wl_doc.exists:
                wl_data = wl_doc.to_dict() or {}
                stored_repo = wl_data.get("github_repo")
                vcs_provider = wl_data.get("vcs_provider") or ("SERVERLESS_GIT" if (stored_repo and "serverless-git" in str(stored_repo).lower()) else "GITHUB")
        except Exception:
            pass

        _, _, full_repo = resolve_repo_identity(stored_repo, product_id=product_id)

        try:
            docs = (
                db.collection("workloads")
                .document(product_id)
                .collection("implementation_plans")
                .order_by("created_at", direction=firestore.Query.DESCENDING)
                .limit(50)
                .stream()
            )
            for d in docs:
                data = d.to_dict() or {}
                fname = data.get("plan_filename", d.id)
                if not fname.endswith(".md"):
                    fname = f"{fname}.md"
                fpath = data.get("plan_file_path", f"docs/planning/{fname}")
                plan_url = f"/api/workloads/{product_id}/plans/{fname}/raw" if vcs_provider == "SERVERLESS_GIT" else f"https://github.com/{full_repo}/blob/main/{fpath}"
                plans.append(
                    WorkloadPlanItem(
                        filename=fname,
                        file_path=fpath,
                        title=data.get("title", f"Architecture Plan: {fname}"),
                        status=data.get("status", "PLANNED"),
                        tier=data.get("tier", 1),
                        created_at=data.get("created_at"),
                        trace_id=data.get("trace_id"),
                        url=plan_url,
                        markdown=data.get("markdown"),
                    )
                )
        except Exception as e:
            logger.warning(f"Could not read implementation plans subcollection for {product_id}: {e}")
            try:
                docs = (
                    db.collection("implementation_plans")
                    .where("product_id", "==", product_id)
                    .stream()
                )
                for d in docs:
                    data = d.to_dict() or {}
                    fname = data.get("plan_filename", d.id)
                    if not fname.endswith(".md"):
                        fname = f"{fname}.md"
                    fpath = data.get("plan_file_path", f"docs/planning/{fname}")
                    plan_url = f"/api/workloads/{product_id}/plans/{fname}/raw" if vcs_provider == "SERVERLESS_GIT" else f"https://github.com/{full_repo}/blob/main/{fpath}"
                    plans.append(
                        WorkloadPlanItem(
                            filename=fname,
                            file_path=fpath,
                            title=data.get("title", f"Architecture Plan: {fname}"),
                            status=data.get("status", "PLANNED"),
                            tier=data.get("tier", 1),
                            created_at=data.get("created_at"),
                            trace_id=data.get("trace_id"),
                            url=plan_url,
                            markdown=data.get("markdown"),
                        )
                    )
            except Exception as fallback_e:
                logger.warning(f"Fallback implementation plans query failed: {fallback_e}")

    # Fallback to discovering plans directly from the repository tree (via private OIDC on Serverless Git or GitHub)
    if not plans and VCSProviderFactory is not None:
        try:
            vcs = VCSProviderFactory.get_provider(provider_name=vcs_provider, product_id=product_id)
            tree = vcs.fetch_file_tree(product_id, branch="main", require_complete=True)   # FD-4DC
            for fpath, fcontent in (tree or {}).items():
                clean_p = fpath.lstrip("/")
                if clean_p.startswith("docs/planning/") and clean_p.endswith(".md"):
                    fname = clean_p.split("/")[-1]
                    plan_url = f"/api/workloads/{product_id}/plans/{fname}/raw" if vcs_provider == "SERVERLESS_GIT" else f"https://github.com/{full_repo}/blob/main/{clean_p}"
                    plans.append(
                        WorkloadPlanItem(
                            filename=fname,
                            file_path=clean_p,
                            title=f"Architecture Plan: {fname}",
                            status="PLANNED",
                            tier=1,
                            created_at=None,
                            trace_id="vcs-repo",
                            url=plan_url,
                            markdown=fcontent if isinstance(fcontent, str) and fcontent else None,
                        )
                    )
        except IncompleteRepoTreeError as tree_err:
            # FD-4DC: a partial tree is never listed as "the plans in the repository" (nor replaced by the baseline)
            logger.warning(f"Plans of {product_id} not listed from the repository: {tree_err}")
            raise _repo_tree_incomplete(tree_err, "No plans were listed from the repository.")
        except Exception as tree_err:
            logger.debug(f"Could not discover plans from VCS tree for {product_id}: {tree_err}")

    # Synthesize initial baseline plan if none exist in database or repository yet
    if not plans:
        base_url = f"/api/workloads/{product_id}/plans/0001-initial-workload-architecture.md/raw" if vcs_provider == "SERVERLESS_GIT" else f"https://github.com/{full_repo}/blob/main/docs/planning/0001-initial-workload-architecture.md"
        plans.append(
            WorkloadPlanItem(
                filename="0001-initial-workload-architecture.md",
                file_path="docs/planning/0001-initial-workload-architecture.md",
                title=f"Initial Workload Architecture for {product_id}",
                status="PLANNED",
                tier=1,
                created_at="2026-09-05T00:00:00Z",
                trace_id="baseline-init",
                url=base_url,
                markdown=f"""---
title: "Initial Workload Architecture for {product_id}"
product_id: "{clean_pid}"
trace_id: "baseline-init"
date: "2026-09-05"
tier: 1
status: "PLANNED"
author: "StackVend Autonomous Engineering Pipeline"
reviewers: ["Architect Agent", "Compliance Agent", "QA Agent"]
approved_by: "Autonomous Tier 1/2 Policy"
---

# Implementation Plan: Initial Workload Architecture for {product_id}

## 1. Executive Summary & Requirements
- **Problem Statement**: Greenfield workload deployment for `{product_id}`.
- **Acceptance Criteria**:
- [ ] Autonomous Cloud Run v2 containerized microservice deployed
- [ ] Firestore native database collection provisioned
- [ ] Scoped Workload Identity Federation IAM permissions bound

## 2. Architecture & Topology Design
- Microservice deployed to Cloud Run v2 with native Firestore database.

## 3. Security, IAM & Governance Assessment
- Runtime Service Account: `sa-{clean_pid}@{project_id or 'project-id'}.iam.gserviceaccount.com`
- Scoped roles: `roles/datastore.user`, `roles/logging.logWriter`

## 4. Component Manifest & Proposed Changes
- `infra/workload/main.tf`
- `apps/service/main.py`
- `docs/planning/0001-initial-workload-architecture.md`

## 5. Sequenced Build Plan (Task DAG)
1. STEP-01: Foundation GCP APIs
2. STEP-02: Firestore Database
3. STEP-03: Workload IAM
4. STEP-04: Application Source Code
5. STEP-05: CI/CD Deployment Workflows
6. STEP-06: Sandbox QA Verification

## 6. Verification & Automated Test Strategy
- Pytest unit suite with 100% pass criteria.

## 7. Rollback & Blast Radius Assessment
- Isolated strictly to `{clean_pid}` namespace.
""",
            )
        )

    return WorkloadPlansResponse(
        product_id=product_id,
        total_plans=len(plans),
        plans=plans,
    )


@router.get("/api/workloads/{product_id}/plans/{filename}", dependencies=[require(WORKLOAD())])
def get_workload_plan_content(product_id: str, filename: str, request: Request):
    verify_workload_access(product_id, request)
    """Retrieves full Markdown content of a specific implementation plan."""
    clean_fn = filename.strip()
    if not clean_fn.endswith(".md"):
        clean_fn = f"{clean_fn}.md"
    base_name = clean_fn.split("/")[-1]
    rel_path = clean_fn if clean_fn.startswith("docs/planning/") else f"docs/planning/{clean_fn}"

    vcs_provider = "GITHUB"
    if db:
        try:
            wl_doc = db.collection("workloads").document(product_id).get()
            if wl_doc.exists:
                wl_data = wl_doc.to_dict() or {}
                stored_repo = wl_data.get("github_repo")
                vcs_provider = wl_data.get("vcs_provider") or ("SERVERLESS_GIT" if (stored_repo and "serverless-git" in str(stored_repo).lower()) else "GITHUB")
        except Exception:
            pass

        try:
            doc = db.collection("workloads").document(product_id).collection("implementation_plans").document(base_name).get()
            if doc.exists:
                data = doc.to_dict() or {}
                md = data.get("markdown", "")
                if md:
                    return {
                        "filename": base_name,
                        "product_id": product_id,
                        "markdown": md,
                        "file_path": data.get("plan_file_path", rel_path),
                        "status": data.get("status", "PLANNED"),
                        "trace_id": data.get("trace_id", ""),
                    }
            doc_global = db.collection("implementation_plans").document(f"{product_id}_{base_name}").get()
            if doc_global.exists:
                data = doc_global.to_dict() or {}
                md = data.get("markdown", "")
                if md:
                    return {
                        "filename": base_name,
                        "product_id": product_id,
                        "markdown": md,
                        "file_path": data.get("plan_file_path", rel_path),
                        "status": data.get("status", "PLANNED"),
                        "trace_id": data.get("trace_id", ""),
                    }
        except Exception as e:
            logger.warning(f"Failed to fetch plan document from Firestore: {e}")

    # Fallback to fetching directly from VCS repository via authenticated OIDC
    if VCSProviderFactory is not None:
        try:
            vcs = VCSProviderFactory.get_provider(provider_name=vcs_provider, product_id=product_id)
            content = vcs.fetch_file_content(product_id, rel_path, branch="main")
            if content:
                return {
                    "filename": base_name,
                    "product_id": product_id,
                    "markdown": content,
                    "file_path": rel_path,
                    "status": "PLANNED",
                    "trace_id": "vcs-source",
                }
        except Exception as vcs_err:
            logger.warning(f"Failed to fetch plan '{rel_path}' from VCS for {product_id}: {vcs_err}")

    if clean_fn.endswith(".md"):
        return {
            "filename": base_name,
            "product_id": product_id,
            "markdown": f"# Implementation Plan: {base_name}\n\nPlan for `{product_id}` stored in `{rel_path}` in child workload repository.",
            "file_path": rel_path,
            "status": "PLANNED",
            "trace_id": "auto",
        }
    raise HTTPException(status_code=404, detail="Implementation plan not found")


@router.get("/api/workloads/{product_id}/plans/{filename}/raw", dependencies=[require(WORKLOAD())])
def get_workload_plan_raw(product_id: str, filename: str, request: Request):
    verify_workload_access(product_id, request)
    """Directly returns raw Markdown text for an implementation plan with text/markdown header."""
    plan_info = get_workload_plan_content(product_id, filename, request)
    content = plan_info.get("markdown", "")
    return Response(content=content, media_type="text/markdown; charset=utf-8")


def _latest_product_execution(product_id: str) -> Dict[str, Any]:
    """The most recent pipeline_executions document of the product (same query and ordering as the failure-aware
    routing below), or {} when there is none or it cannot be read."""
    try:
        runs = [d.to_dict() or {} for d in
                db.collection("pipeline_executions").where("product_id", "==", product_id).limit(25).stream()]
    except Exception as e:  # noqa: BLE001 - no prior record found; the developer then fails closed (typed)
        logger.warning(f"Could not read prior executions of '{product_id}': {e}")
        return {}
    runs = [r for r in runs if r]
    runs.sort(key=lambda x: str(x.get("started_at", "") or x.get("created_at", "")), reverse=True)
    return runs[0] if runs else {}


# TI-5-R3-d (owner 10-25, FOLLOWUPS-1025): a RESUME_DEVELOPER relaunch forwards the failed deploy's typed validation
# report, so the developer plans exactly as on an in-run terraform remediation (developer_agent/deploy_repair.py). The
# report is read from the source execution's terraform stage record (shared/callbacks.py writes it beside the error it
# belongs to) and written to the new execution's record, never into the Pub/Sub / workflow arguments; the gateway
# reads it on the run's first developer dispatch (orchestrator-gateway main._resume_validation_report).
RESUME_TF_VALIDATION_REPORT_FIELD = "resume_tf_validation_report"


def _resume_validation_report(source_exec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """{"validation_report": <dict>, "source_trace_id": <trace>} when the source execution's terraform stage FAILED
    and its record holds a report written for exactly that stage write: `validation_report_attempt` equals the stage's
    `attempt_id` (shared/callbacks.py, RT 11-07 F1) and `validation_report_error` its `error`; else None (no report,
    a deploy that succeeded later, or a later failure without a report, even with the same error: never an older one)."""
    stages = source_exec.get("stages") if isinstance(source_exec, dict) else None
    tf = stages.get("terraform") if isinstance(stages, dict) else None
    if not isinstance(tf, dict) or tf.get("status") != "FAILED":
        return None
    report, trace = tf.get("validation_report"), source_exec.get("trace_id")
    if not isinstance(report, dict) or not isinstance(trace, str) or not trace:
        return None
    attempt = tf.get("attempt_id")
    if (not isinstance(attempt, str) or not attempt or tf.get("validation_report_attempt") != attempt
            or "validation_report_error" not in tf or tf.get("validation_report_error") != tf.get("error")):
        logger.info(f"Resume of trace {trace}: the stored deploy validation report belongs to an earlier failure; "
                    "not forwarded")
        return None
    return {"validation_report": report, "source_trace_id": trace}


# RESUME-DEVELOPER-TASK-DAG: whether a RESUME_DEVELOPER relaunch can pass the gateway's /agent/resume/outcome. These
# mirror the gateway's workflow_gates (RESUMABLE_GATE_STATUSES, TASK_DAG_*); tests/test_resume_developer_task_dag.py
# keeps them equal.
RESUMABLE_GATE_STATUSES = ("PASS", "APPROVED")
TASK_DAG_COLLECTION = "prebuild_task_dags"
TASK_DAG_STORED = "STORED"
TASK_DAG_TOO_LARGE = "TOO_LARGE"
RESUME_CHECK_UNREADABLE = "RESUME_CHECK_UNREADABLE"
_RESUME_BLOCK_TEXT = {
    "NO_REUSABLE_PREBUILD_GATE": "this workload has no earlier full build that passed its pre-build gate",
    "OTHER_FEATURE_REQUEST": "the last full build that passed its pre-build gate built a different feature request",
    "NO_PERSISTED_TASK_DAG": "no task plan is saved for the last full build",
    "TASK_DAG_TOO_LARGE": "the task plan of the last full build was too large to save",
}


def _resume_developer_block(product_id: str, request_id: str, w_data: Dict[str, Any]) -> Optional[str]:
    """Why a RESUME_DEVELOPER relaunch of this feature request cannot succeed, None when nothing stands in its way: the
    last pre-build gate must be a passed one of this workload, its run must have built this feature request (when the
    run recorded one) and its Task DAG must be kept for that gate. RESUME_CHECK_UNREADABLE: not known either way."""
    gate = w_data.get("last_prebuild_gate")
    gate_trace = gate.get("trace_id") if isinstance(gate, dict) else None
    if (not isinstance(gate, dict) or gate.get("status") not in RESUMABLE_GATE_STATUSES
            or gate.get("product_id") != product_id or not isinstance(gate_trace, str) or not gate_trace):
        return "NO_REUSABLE_PREBUILD_GATE"
    try:
        gate_run = db.collection("pipeline_executions").document(gate_trace).get()
        built_request = (gate_run.to_dict() or {}).get("request_id") if gate_run.exists else None
        snap = (db.collection("workloads").document(product_id)
                .collection(TASK_DAG_COLLECTION).document(gate_trace).get())
        record = (snap.to_dict() or {}) if snap.exists else None
    except Exception as e:  # noqa: BLE001 - not known to be possible: refused as such, never assumed either way
        logger.warning(f"Could not read the resume records of '{product_id}' trace {gate_trace}: {type(e).__name__}: {e}")
        return RESUME_CHECK_UNREADABLE
    if built_request is not None and built_request != request_id:
        return "OTHER_FEATURE_REQUEST"
    if (not isinstance(record, dict) or record.get("product_id") != product_id or record.get("trace_id") != gate_trace
            or record.get("rework_cycle") != gate.get("rework_cycle")):
        return "NO_PERSISTED_TASK_DAG"
    if record.get("status") == TASK_DAG_TOO_LARGE:
        return "TASK_DAG_TOO_LARGE"
    task_count = record.get("task_count")
    if record.get("status") != TASK_DAG_STORED or not isinstance(task_count, int) or task_count <= 0:
        return "NO_PERSISTED_TASK_DAG"
    return None


def _resume_refusal(block: str) -> HTTPException:
    """The typed refusal of a RESUME_DEVELOPER relaunch that cannot succeed, or (503, Auto too) could not be checked;
    `detail.message` is the toast."""
    if block == RESUME_CHECK_UNREADABLE:
        return HTTPException(status_code=503, detail={
            "error_class": "RESUME_CHECK_UNAVAILABLE", "reason": block,
            "message": "Could not check whether this workload can be resumed (its saved task plan could not be read). "
                       "Try again, or relaunch with Full Swarm Rebuild."})
    return HTTPException(status_code=409, detail={
        "error_class": "RESUME_NOT_AVAILABLE", "reason": block,
        "message": f"This workload cannot be resumed: {_RESUME_BLOCK_TEXT[block]}. "
                   "Relaunch with Full Swarm Rebuild instead."})


# FD-4DT (B): Auto relaunch after a success whose only change is the access record -> Fast-Path Deploy.
ACCESS_SET_AUDIT_ACTION = "WORKLOAD_ACCESS_SET"   # update_workload_access's audit entries
_FAST_PATH_ACCESS_MODES = frozenset({"PRIVATE_IAM", "PRIVATE_IAP"})   # deploy_access_tfvars renders these only


def _parse_utc(value: Any) -> Optional[datetime]:
    """An ISO-8601 timestamp string with a UTC offset (``...+00:00`` or ``...Z``) as an aware datetime, else None."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def access_only_fast_path(*, prev_exec: Any, request_id: str, feature_request: Any, workload: Any,
                          load_feature_requests, load_access_audit) -> Tuple[bool, str]:
    """FD-4DT (B): (True, "ACCESS_ONLY_CHANGE") when an Auto relaunch may use Fast-Path Deploy (DEPLOY_ONLY) because the
    workload's last run SUCCEEDED and the only change since is its access record; otherwise (False, <reason>) and Auto
    routes as before. Typed fields and parsed timestamps only (no text matching):

    1. the latest run's ``status`` is exactly ``SUCCEEDED`` with parseable ``started_at`` / ``completed_at``;
    2. not an Express workload (``creation_mode`` EXPRESS: its access is rendered at an Express submit);
    3. the run built this feature request (its ``request_id``, when recorded, equals the retriggered one);
    4. ``access_updated_at`` is later than the run's ``completed_at``;
    5. no widening waits for its plan approval (DEPLOY_ONLY is refused then; a full build gets the approval);
    6. the current record is a valid private record (the deploy applies only PRIVATE_IAM / PRIVATE_IAP records);
    7. no spec change: no feature request of the workload was created after the run started, and the retriggered one
       was not updated after it started (``load_feature_requests()``: the workload's feature request documents);
    8. every access change since the run completed (``load_access_audit()``: the workload's ``WORKLOAD_ACCESS_SET``
       audit entries) was between private records (a change to or from Public regenerates the app: full build);
    9. APP-ADMIN-IAP-CONTRACT: when the workload carries the developer's ``app_admin_contract`` (a Direct IAP Cloud Run
       build rendered an app administrator list), the list the CURRENT record gives
       (``shared.access_policy.effective_app_admin_emails`` with the workload's verified submitter) has the recorded
       ``admin_list_sha256``; otherwise ``APP_ADMIN_CHANGE`` (the list lives in the generated Terraform: a full build
       renders it; a Fast-Path Deploy would keep the old one). No record: unchanged.
    A loader that raises, or a timestamp that does not parse, gives (False, ...): Auto keeps its previous routing."""
    if not isinstance(prev_exec, dict) or prev_exec.get("status") != "SUCCEEDED":
        return False, "LAST_RUN_NOT_SUCCEEDED"
    started, completed = _parse_utc(prev_exec.get("started_at")), _parse_utc(prev_exec.get("completed_at"))
    if started is None or completed is None:
        return False, "RUN_TIMES_UNREADABLE"
    if not isinstance(workload, dict) or workload.get("creation_mode") == "EXPRESS":
        return False, "EXPRESS_WORKLOAD"
    built_request = prev_exec.get("request_id")
    if built_request is not None and built_request != request_id:
        return False, "OTHER_FEATURE_REQUEST"
    access_updated = _parse_utc(workload.get("access_updated_at"))
    if access_updated is None or access_updated <= completed:
        return False, "NO_ACCESS_CHANGE_SINCE_SUCCESS"
    if workload.get(ACCESS_WIDENING_APPROVAL_FIELD) is not None:
        return False, "ACCESS_WIDENING_PENDING"
    policy = stored_access_policy(workload.get("access"))
    if policy is None or policy.mode.value not in _FAST_PATH_ACCESS_MODES or not policy.is_complete:
        return False, "ACCESS_RECORD_NOT_PRIVATE"
    contract = workload.get(APP_ADMIN_CONTRACT_FIELD)
    if contract is not None:
        admins, _source = effective_app_admin_emails(policy, workload_verified_submitter(workload))
        if not isinstance(contract, dict) or contract.get("admin_list_sha256") != app_admin_list_digest(admins):
            return False, "APP_ADMIN_CHANGE"
    fr_updated = (feature_request or {}).get("updated_at") if isinstance(feature_request, dict) else None
    if fr_updated is not None and (_parse_utc(fr_updated) is None or _parse_utc(fr_updated) > started):
        return False, "FEATURE_REQUEST_CHANGED"
    try:
        feature_requests = list(load_feature_requests())
        audit_entries = list(load_access_audit())
    except Exception:  # noqa: BLE001 - unknown history: keep the previous routing
        return False, "HISTORY_UNREADABLE"
    for fr in feature_requests:
        created = _parse_utc(fr.get("created_at")) if isinstance(fr, dict) else None
        if created is None or created > started:
            return False, "NEW_FEATURE_REQUEST"
    changes = 0
    for entry in audit_entries:
        if not isinstance(entry, dict) or entry.get("action") != ACCESS_SET_AUDIT_ACTION:
            continue
        at = _parse_utc(entry.get("timestamp"))
        if at is None:
            return False, "HISTORY_UNREADABLE"
        if at <= completed:
            continue
        changes += 1
        for side in ("previous_access", "new_access"):
            rec = entry.get(side)
            if not isinstance(rec, dict) or rec.get("mode") not in _FAST_PATH_ACCESS_MODES:
                return False, "ACCESS_MODE_CHANGE_NEEDS_REBUILD"
    if changes == 0:
        return False, "HISTORY_UNREADABLE"   # access_updated_at moved but no audit entry says how
    return True, "ACCESS_ONLY_CHANGE"


# DEPLOY-FAILURE-OWNER-ROUTER RT F2 (owner 11-13): the terraform server records who can change what made a deploy fail
# (pipeline_executions/{trace}.stages.terraform.failure_route.owner; mcp-servers/terraform/deploy_failure_router.OWNERS,
# parity test tests/test_deploy_failure_owner_router_cc.py). Auto never sends a failure the developer does not own back
# to the developer: these owners relaunch as Fast-Path Deploy (0 LLM) and skip the error-text phrase test.
DEPLOY_FAILURE_NON_DEVELOPER_OWNERS = frozenset({"PLATFORM_DEFECT", "OPERATOR_REQUIRED", "PROVIDER_TRANSIENT",
                                                 "UNKNOWN"})


def typed_deploy_failure_owner(tf_info: Any) -> Optional[str]:
    """The typed owner of the run's failed deploy: `stages.terraform.failure_route.owner` when the terraform stage is
    FAILED (a route left by an earlier failure of a stage that later succeeded is not read); else None."""
    if not isinstance(tf_info, dict) or str(tf_info.get("status") or "").upper() != "FAILED":
        return None
    route = tf_info.get("failure_route")
    owner = route.get("owner") if isinstance(route, dict) else None
    return owner if isinstance(owner, str) and owner else None


def _access_only_fast_path_for(product_id: str, request_id: str, prev_exec: Any, feature_request: Any,
                               workload: Any) -> Tuple[bool, str]:
    """`access_only_fast_path` with the Firestore loaders (only read when the cheap checks pass)."""
    def _feature_requests():
        return [d.to_dict() or {} for d in db.collection("feature_requests").where("product_id", "==", product_id)
                .stream()]

    def _access_audit():
        return [d.to_dict() or {} for d in db.collection("workloads").document(product_id).collection("audit_logs")
                .where("action", "==", ACCESS_SET_AUDIT_ACTION).stream()]

    return access_only_fast_path(prev_exec=prev_exec, request_id=request_id, feature_request=feature_request,
                                 workload=workload, load_feature_requests=_feature_requests,
                                 load_access_audit=_access_audit)


PLATFORM_WORKLOAD_RUN_REFUSED = "PLATFORM_WORKLOAD_RUN_REFUSED"


def _refuse_platform_workload_run(product_id: str, workload: Dict[str, Any], host_project: str, action: str) -> None:
    """RT14 RT F5: a retrigger or Fast-Path re-apply of the StackVend platform record (a platform pseudo-id, a record
    with ``is_castor: true`` or a record whose ``project_id`` is the host project) is refused with 400 before anything
    is written or published. The gateway refuses that event on every non-autonomous channel (RT14-02), so it used to be
    answered as sent and fail afterwards. Exact comparisons only (the gateway's rule)."""
    host = (host_project or "").strip()
    if (product_id in PLATFORM_PSEUDO_WORKLOADS or workload.get("is_castor") is True
            or (host and workload.get("project_id") == host)):
        raise HTTPException(status_code=400, detail={
            "code": PLATFORM_WORKLOAD_RUN_REFUSED, "product_id": product_id,
            "detail": f"The StackVend platform workload cannot be the target of a {action}; nothing was started."})


@router.post("/api/workloads/{product_id}/feature-requests/{request_id}/retrigger", dependencies=[require(WORKLOAD_CHILD("request_id", "feature_requests", manager=True, child_field="request_id"))])
def retrigger_feature_request_build(
    product_id: str,
    request_id: str,
    request: Request,
    body: Optional[Dict[str, Any]] = None,
):
    verify_workload_access(product_id, request, require_manager=True)
    _refuse_new_run_in_maintenance("retrigger")  # settings-toggles (also retrigger_workload_latest)
    """
    Manually re-dispatches a feature request specification to Pub/Sub to restart or resume the multi-agent pipeline.
    Implements Failure-Aware Retrigger Routing (Red Team Hardened):
    - CLASS 2 LATE FAILURE: If prior execution failed post-merge (TERRAFORM or SRE), auto-routes to DEPLOY_ONLY (0 LLM, <60s).
    - CLASS 1 MID FAILURE: If prior execution failed at DEVELOPER/QA, auto-routes to RESUME_DEVELOPER (skipping Architect).
    - ACCESS-ONLY CHANGE (FD-4DT): the last run SUCCEEDED and only the access record changed since (between private
      records, no widening pending, no new spec): auto-routes to DEPLOY_ONLY, which applies the current record.
    - GREENFIELD: Dispatches FULL multi-agent synthesis.
    """
    admin_email = getattr(request.state, "user_email", "admin-console")
    main_mod = get_caller_main_module()
    current_project = getattr(main_mod, "project_id", None) or project_id or os.getenv("PROJECT_ID", "")

    if not db:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")

    doc = db.collection("feature_requests").document(request_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Feature request not found")

    data = doc.to_dict() or {}
    # FD-4N (red-team B1/H1): the feature request must belong to this workload (exact). This also covers the
    # internal call from retrigger_workload_latest, whose request_id comes from an agent-written execution doc.
    if data.get("product_id") != product_id:
        raise HTTPException(status_code=404, detail="Feature request not found")

    # Deploy targets (GCP project, repository, branch) come ONLY from workloads/{product_id}; never from the
    # feature-request doc or the request body.
    w_snap = db.collection("workloads").document(product_id).get()
    w_data = (w_snap.to_dict() or {}) if w_snap.exists else {}
    _refuse_platform_workload_run(product_id, w_data, current_project, "retrigger")  # RT14 RT F5
    target_project_id = w_data.get("project_id")
    github_repo = w_data.get("github_repo")
    workload_branch = (w_data.get("default_branch") or "main").strip()
    if not w_snap.exists or not target_project_id or not github_repo:
        raise HTTPException(
            status_code=409,
            detail=f"Workload '{product_id}' has no registered project_id/github_repo; cannot retrigger.",
        )
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Resolve execution mode (operator choice, allow-listed); branch is the workload's registered branch
    explicit_mode = None
    target_branch = workload_branch
    pull_request_url = ""
    prev_exec = {}
    prev_error = ""
    tf_info = {}
    auto_fallback: Dict[str, str] = {}   # why Auto did not take the path it first chose (empty: it did)

    if body and isinstance(body, dict):
        if body.get("execution_mode"):
            explicit_mode = str(body["execution_mode"]).upper()
            if explicit_mode not in ("AUTO", "DEFAULT", "NONE", "FULL", "RESUME_DEVELOPER", "DEPLOY_ONLY"):
                raise HTTPException(status_code=400, detail=f"Unsupported execution_mode '{explicit_mode}'.")
        requested_branch = str(body.get("target_branch") or "").strip()
        if requested_branch and requested_branch != workload_branch:
            raise HTTPException(
                status_code=400,
                detail=f"target_branch is fixed to the workload's registered branch '{workload_branch}'.",
            )

    # If explicit execution_mode was requested by operator, honor it unless AUTO is specified
    if explicit_mode and explicit_mode not in ("AUTO", "DEFAULT", "NONE", ""):
        execution_mode = explicit_mode
        logger.info(f"Workload '{product_id}' retrigger honoring explicit operator execution_mode: {execution_mode}")
    else:
        # Fallback to failure-aware routing heuristics when AUTO or no explicit mode provided
        execution_mode = "FULL"
        if db:
            try:
                exec_docs = list(
                    db.collection("pipeline_executions")
                    .where("product_id", "==", product_id)
                    .limit(25)
                    .stream()
                )
                recent_runs = []
                for d in exec_docs:
                    rdata = d.to_dict() or {}
                    if rdata:
                        recent_runs.append(rdata)
                recent_runs.sort(key=lambda x: str(x.get("started_at", "") or x.get("created_at", "")), reverse=True)

                if recent_runs:
                    prev_exec = recent_runs[0]
                    prev_status = (prev_exec.get("status") or "").upper()
                    prev_stage = (prev_exec.get("current_stage") or "").upper()
                    prev_mode = (prev_exec.get("execution_mode") or "").upper()
                    prev_error = str(prev_exec.get("error") or prev_exec.get("error_detail") or "").lower()
                    prev_stages = prev_exec.get("stages", {}) or {}

                    tf_info = prev_stages.get("terraform") or {}
                    tf_status = (tf_info.get("status") or "").upper()
                    tf_state = (tf_info.get("state") or "").upper()
                    dev_status = ((prev_stages.get("developer") or {}).get("status") or "").upper()

                    # Derive true terminal stage from stages dict if current_stage is FAILED, ABORTED, or generic
                    terminal_stage = prev_stage
                    if prev_stage in ["FAILED", "ABORTED", "COMPLETE", ""] and prev_stages:
                        for stg in ["sre", "terraform", "release", "qa", "developer", "vending", "compliance", "architect"]:
                            stg_info = prev_stages.get(stg) or {}
                            stg_status = (stg_info.get("status") or "").upper()
                            stg_state = (stg_info.get("state") or "").upper()
                            if stg_status in ["FAILED", "IN_FLIGHT"] or stg_state in ["FAILED", "CALLBACK_FAILED"]:
                                terminal_stage = stg.upper()
                                break

                    # Also infer terminal_stage if root error, previous mode, or tf state explicitly indicates IaC
                    if terminal_stage in ["FAILED", "ABORTED", ""] and (prev_mode == "DEPLOY_ONLY" or "terraform" in prev_error or "tofu" in prev_error or tf_state in ["CALLBACK_FAILED", "FAILED"]):
                        terminal_stage = "TERRAFORM"

                    is_late_stage = any(k in terminal_stage for k in ["TERRAFORM", "DEPLOY", "SRE"]) or prev_mode == "DEPLOY_ONLY" or tf_state in ["CALLBACK_FAILED", "FAILED"] or ("terraform" in prev_error or "tofu" in prev_error)
                    is_mid_stage = any(k in terminal_stage for k in ["DEVELOPER", "QA", "GATEKEEPER", "RELEASE"])

                    # FD-4DT (B): a success followed only by an access-record change -> Fast-Path Deploy, which
                    # applies the current record (typed signals only; see access_only_fast_path).
                    access_only, access_only_reason = _access_only_fast_path_for(
                        product_id, request_id, prev_exec, data, w_data)
                    if prev_status == "SUCCEEDED" and not access_only:
                        logger.info(f"Workload '{product_id}': last run succeeded; access-only Fast-Path not "
                                    f"chosen ({access_only_reason}).")

                    if access_only:
                        execution_mode = "DEPLOY_ONLY"
                        logger.info(f"Workload '{product_id}': the last run succeeded and only its access record "
                                    "changed since. Auto-routing to Fast-Path Deploy (DEPLOY_ONLY, 0 LLM), which "
                                    "applies the current access record.")
                    elif prev_status == "FAILED" or tf_status == "FAILED" or is_late_stage:
                        if is_late_stage or tf_status == "FAILED" or tf_state in ["CALLBACK_FAILED", "FAILED"]:
                            # Inspect error text to distinguish code/module defects from transient infrastructure failures
                            tf_error = str(tf_info.get("error") or prev_error).lower()
                            # DEPLOY-FAILURE-OWNER-ROUTER RT F2: a typed non-developer owner decides first (never
                            # RESUME_DEVELOPER from the error text for a failure the developer cannot change)
                            typed_owner = typed_deploy_failure_owner(tf_info)
                            is_code_defect = typed_owner not in DEPLOY_FAILURE_NON_DEVELOPER_OWNERS and any(
                                err_kw in tf_error for err_kw in [
                                    "unreadable module", "no such file or directory", "syntax error",
                                    "reference to undeclared", "unbalanced braces", "error: module not found"
                                ])
                            if typed_owner in DEPLOY_FAILURE_NON_DEVELOPER_OWNERS:
                                logger.info(f"Workload '{product_id}' prior deploy failure is owned by {typed_owner} "
                                            "(typed route): not the developer's.")
                            if is_code_defect:
                                # Code / Module defect: must heal and commit via Developer Agent rather than naive DEPLOY_ONLY
                                execution_mode = "RESUME_DEVELOPER"
                                logger.info(f"Workload '{product_id}' prior build failed at {terminal_stage} due to code/module defect: '{tf_error[:100]}...'. Auto-routing to RESUME_DEVELOPER for automated healing.")
                            else:
                                # CLASS 2 LATE FAILURE: Transient/infra failure, code on main is valid, route directly to Fast-Path IaC Apply!
                                execution_mode = "DEPLOY_ONLY"
                                logger.info(f"Workload '{product_id}' prior build failed post-merge at stage '{terminal_stage or 'TERRAFORM'}'. Auto-routing to Fast-Path IaC (DEPLOY_ONLY, 0 LLM).")
                        elif is_mid_stage or dev_status == "FAILED":
                            # CLASS 1 MID FAILURE: Resume Developer retry without re-running Architect
                            execution_mode = "RESUME_DEVELOPER"
                            logger.info(f"Workload '{product_id}' prior build failed at stage '{terminal_stage}'. Auto-routing to RESUME_DEVELOPER.")
            except Exception as route_err:
                logger.warning(f"Could not compute failure-aware route for '{product_id}': {route_err}")

    # RESUME-DEVELOPER-TASK-DAG: a resume this check knows cannot succeed does not start. Auto goes to a full build and
    # says why (a check that could not read the store decides nothing: refused in both modes); an operator's explicit
    # choice gets a typed refusal. The compliance record and a pending access widening are checked only by the gateway's
    # /agent/resume/outcome, which stays the authority.
    auto_fallback: Dict[str, str] = {}
    if execution_mode == "RESUME_DEVELOPER":
        resume_block = _resume_developer_block(product_id, request_id, w_data)
        if resume_block:
            if explicit_mode == "RESUME_DEVELOPER" or resume_block == RESUME_CHECK_UNREADABLE:
                raise _resume_refusal(resume_block)
            execution_mode = "FULL"
            auto_fallback = {"auto_fallback_reason": resume_block,
                             "auto_fallback_message": f"Auto could not resume this build ({_RESUME_BLOCK_TEXT[resume_block]}), "
                                                      "so it started a Full Swarm Rebuild."}
            logger.warning(f"Workload '{product_id}': Auto routing chose RESUME_DEVELOPER, but a resume cannot succeed "
                           f"({resume_block}); falling back to a FULL build.")

    # RT fix 1 (FH-7): a RESUME_DEVELOPER relaunch skips the architect, so it carries the architect's typed compute
    # record forward from the previous execution (the developer reads pipeline_executions/{trace}.architect_compute_intent
    # and fails closed without it). Only a recorded dict is copied; nothing is fabricated.
    resume_compute_intent = None
    resume_tf_report = None
    if execution_mode == "RESUME_DEVELOPER":
        source_exec = prev_exec or _latest_product_execution(product_id)
        prior_ci = source_exec.get("architect_compute_intent")
        if isinstance(prior_ci, dict) and prior_ci:
            resume_compute_intent = dict(prior_ci, copied_from_trace=source_exec.get("trace_id"))
        resume_tf_report = _resume_validation_report(source_exec)   # TI-5-R3-d

    # AUTO-DEPLOY-ONLY-OTHER-REQUEST: Fast-Path deploys the code the last run merged, so when that run recorded a
    # different feature request Auto starts a full build of this one instead. An operator's explicit Fast-Path is kept,
    # and a run with no recorded id routes as before.
    built_request = prev_exec.get("request_id")
    if (execution_mode == "DEPLOY_ONLY" and explicit_mode != "DEPLOY_ONLY"
            and built_request and built_request != request_id):
        execution_mode = "FULL"
        auto_fallback = {"auto_fallback_reason": "OTHER_FEATURE_REQUEST",
                         "auto_fallback_message": "Auto could not use Fast-Path Deploy (the last run built a different "
                                                  "feature request), so it started a Full Swarm Rebuild."}
        logger.warning(f"Workload '{product_id}': Auto routing chose DEPLOY_ONLY for '{request_id}', but the last run "
                       f"built '{built_request}'; falling back to a FULL build.")

    # RT14-07: a Fast-Path relaunch (explicit, or chosen by Auto) of an Express workload whose last deploy was refused
    # for unapproved removals would apply that refused configuration; refused exactly as /deploy-infra refuses it.
    if execution_mode == "DEPLOY_ONLY":
        _refuse_open_express_destroy_refusal(w_data)

    # Dispatch to spec-intake-events Pub/Sub topic
    active_pubsub_getter = getattr(main_mod, "get_pubsub_publisher", get_pubsub_publisher)
    pub_client = active_pubsub_getter()
    if pub_client and current_project:
        try:
            intake_topic = f"projects/{current_project}/topics/spec-intake-events"
            prefix = "fastpath" if execution_mode == "DEPLOY_ONLY" else ("resume" if execution_mode == "RESUME_DEVELOPER" else "retry")
            trace_id = f"{prefix}-{product_id}-{uuid.uuid4().hex[:6]}"

            intake_payload = {
                "trace_id": trace_id,
                "product_id": product_id,
                "project_id": target_project_id,
                "target_project_id": target_project_id,
                "github_repo": github_repo,
                "title": data.get("title", f"Build: {product_id}"),
                "spec_text": data.get("description", ""),
                "source_channel": "control_center_retrigger",
                "created_at": now_iso,
                "budget_ceiling_monthly_usd": float(w_data.get("budget_ceiling_monthly_usd", 50.0)),
                "execution_mode": execution_mode,
                "target_branch": target_branch,
                "pull_request_url": pull_request_url,
                "tf_remediation_context": str(tf_info.get("error") or prev_error or "") if (execution_mode == "RESUME_DEVELOPER") else "",
                "task_dag": prev_exec.get("task_dag") or data.get("task_dag") or [],
            }
            if resume_compute_intent is not None:
                intake_payload["architect_compute_intent"] = resume_compute_intent

            # Initialize real-time pipeline execution tracking in Firestore for Flight Deck.
            # STALE-RUN-AUTOFAIL-BOUND (RT F5): written BEFORE the build event is published (as /deploy-infra does),
            # so the gateway's dispatch always attaches its workflow execution to this record and this full write can
            # never wipe that binding; the record carries no workflow_execution_id key (the gateway owns it).
            is_deploy_only = (execution_mode == "DEPLOY_ONLY")
            is_resume_dev = (execution_mode == "RESUME_DEVELOPER")

            initial_execution = {
                "trace_id": trace_id,
                "product_id": product_id,
                "request_id": request_id,
                "feature_title": data.get("title", f"Build: {product_id}"),
                "status": "ACTIVE",
                "current_stage": "TERRAFORM" if is_deploy_only else ("DEVELOPER" if is_resume_dev else "DISCOVERY"),
                "started_at": now_iso,
                "completed_at": None,
                "elapsed_seconds": 0.0,
                "execution_mode": execution_mode,
                **auto_fallback,
                "stages": {
                    "discovery": {
                        "status": "SKIPPED" if is_deploy_only else "IN_FLIGHT",
                        "started_at": now_iso if not is_deploy_only else None,
                        "summary": "Bypassed via Fast-Path (Code already merged on main)" if is_deploy_only else "Harvesting GCP folder organization policies (0 LLM)...",
                    },
                    "architect": {
                        "status": "SKIPPED" if (is_deploy_only or is_resume_dev) else "QUEUED",
                        "summary": "Bypassed via Fast-Path (Zero-LLM)" if (is_deploy_only or is_resume_dev) else "Waiting for org policy discovery",
                    },
                    "compliance": {
                        "status": "SKIPPED" if (is_deploy_only or is_resume_dev) else "QUEUED",
                        "summary": "Bypassed via Fast-Path" if (is_deploy_only or is_resume_dev) else None,
                    },
                    "vending": {
                        "status": "SKIPPED",
                        "summary": "Brownfield project reused",
                    },
                    "developer": {
                        "status": "SKIPPED" if is_deploy_only else ("IN_FLIGHT" if is_resume_dev else "QUEUED"),
                        "started_at": now_iso if is_resume_dev else None,
                        "summary": "Bypassed via Zero-Invocation Invariant (Code merged on main)" if is_deploy_only else ("Resuming developer build" if is_resume_dev else None),
                    },
                    "qa": {
                        "status": "SKIPPED" if is_deploy_only else "QUEUED",
                        "summary": "Bypassed via Fast-Path" if is_deploy_only else None,
                    },
                    "terraform": {
                        "status": "QUEUED",
                        "summary": f"Fast-Path IaC Re-Apply queued (<60s) on branch '{target_branch}'" if is_deploy_only else None,
                    },
                    "sre": {
                        "status": "QUEUED",
                    },
                },
                "outputs": {
                    "github_repo": github_repo,
                    "product_id": product_id,
                    "target_project_id": target_project_id,
                    "target_branch": target_branch,
                    "execution_mode": execution_mode,
                    "pull_request_url": pull_request_url,
                },
            }
            if resume_compute_intent is not None:
                initial_execution["architect_compute_intent"] = resume_compute_intent
            initial_execution.update(auto_fallback)   # RESUME-DEVELOPER-TASK-DAG: why Auto did not resume

            # BUILD-ADMISSION-QUEUE (G4): a Full or Resume Developer build (Auto already resolved) takes a build slot
            # before anything is published; Fast-Path (DEPLOY_ONLY, 0 LLM) never waits. Over the limit the run is
            # recorded QUEUED (its pre-seeded record, written before it joins the queue) and the answer is 202.
            if _build_admission.requires_admission(intake_payload):
                queued_execution = dict(initial_execution, status=_build_admission.RUN_STATUS_QUEUED,
                                        current_stage=_build_admission.RUN_STATUS_QUEUED, queued_at=now_iso)
                admission = build_queue.admit_run(
                    db, trace_id=trace_id, product_id=product_id, payload=intake_payload,
                    source="control_center_retrigger", one_per_product=True,
                    request_status_on_dispatch="IN_DEVELOPMENT", queued_record=queued_execution,
                    overwrite_record=True)
                if admission.state == _build_admission.QUEUED:
                    if resume_tf_report is not None:
                        try:
                            db.collection("pipeline_executions").document(trace_id).set(
                                {RESUME_TF_VALIDATION_REPORT_FIELD: resume_tf_report}, merge=True)
                        except Exception as rr_err:
                            logger.warning(f"Could not persist the forwarded deploy validation report on {trace_id} "
                                           f"(the resumed developer regenerates without it): {rr_err}")
                    build_queue.mark_request_queued(db, request_id, {
                        "last_retriggered_at": now_iso, "retriggered_by": admin_email, "trace_id": trace_id,
                        "execution_mode": execution_mode})
                    if admission.pump_needed:
                        build_queue.reconcile_and_pump(db)
                    logger.info(f"Build for '{product_id}' QUEUED (Mode: {execution_mode}, trace {trace_id}, "
                                f"#{admission.position} in line) by {admin_email}")
                    return JSONResponse(status_code=202, content={
                        "status": _build_admission.QUEUED,
                        "request_id": request_id,
                        "trace_id": trace_id,
                        "execution_mode": execution_mode,
                        "target_branch": target_branch,
                        "build_queue": admission.view(),
                        "message": (f"All {admission.limit} build slot(s) are in use: the build waits in the queue "
                                    f"(#{admission.position} in line) and starts when a running build ends."),
                        **auto_fallback,
                    })
            try:
                db.collection("pipeline_executions").document(trace_id).set(initial_execution)
            except Exception as pe_err:
                logger.warning(f"Could not persist initial pipeline_execution {trace_id}: {pe_err}")
            if resume_tf_report is not None:
                # TI-5-R3-d: its own merge write, so a report the document cannot hold never loses the record above
                try:
                    db.collection("pipeline_executions").document(trace_id).set(
                        {RESUME_TF_VALIDATION_REPORT_FIELD: resume_tf_report}, merge=True)
                except Exception as rr_err:
                    logger.warning(f"Could not persist the forwarded deploy validation report on {trace_id} "
                                   f"(the resumed developer regenerates without it): {rr_err}")

            data_bytes = json.dumps(intake_payload).encode("utf-8")
            try:
                future = pub_client.publish(intake_topic, data_bytes)
                msg_id = future.result(timeout=10.0)
            except (TimeoutError, concurrent.futures.TimeoutError) as timeout_err:
                # The publisher may still deliver the event: the record stays ACTIVE (unbound). If the workflow
                # starts, the gateway attaches it; if not, the Flight Deck closes it after its silence limit
                # (RUN_SILENT_NO_WORKFLOW). Answered like /deploy-infra (504, typed), so nobody retries blindly and
                # starts a second run (red-team delta D1).
                logger.error(f"Retrigger build event publish timed out for '{product_id}' (trace {trace_id}, "
                             f"{type(timeout_err).__name__})")
                raise HTTPException(status_code=504, detail={
                    "code": RETRIGGER_DISPATCH_OUTCOME_UNKNOWN,
                    "error_class": RETRIGGER_DISPATCH_OUTCOME_UNKNOWN,
                    "trace_id": trace_id,
                    "message": (f"The build event publish timed out and may still be delivered, so the build may "
                                f"already be running (trace {trace_id}). Check that run in the Flight Deck before "
                                f"retrying."),
                })
            except Exception as pub_err:
                _fail_retrigger_dispatch(trace_id, pub_err)
                _release_unpublished_build(trace_id)   # BUILD-ADMISSION-QUEUE (a no-op for Fast-Path)
                raise

            # Update feature request status in Firestore to IN_DEVELOPMENT
            db.collection("feature_requests").document(request_id).set({
                "status": "IN_DEVELOPMENT",
                "last_retriggered_at": now_iso,
                "retriggered_by": admin_email,
                "trace_id": trace_id,
                "execution_mode": execution_mode,
            }, merge=True)

            logger.info(f"Re-dispatched build to Pub/Sub for '{product_id}' (Mode: {execution_mode}, Msg ID: {msg_id}) by {admin_email}")
            return {
                "status": "DISPATCHED",
                "request_id": request_id,
                "pubsub_message_id": msg_id,
                "trace_id": trace_id,
                "execution_mode": execution_mode,
                "target_branch": target_branch,
                "execution": initial_execution,
                **auto_fallback,
            }
        except HTTPException:
            raise  # RETRIGGER_DISPATCH_OUTCOME_UNKNOWN (504): already typed
        except Exception as e:
            logger.warning(f"Failed to publish intake event to Pub/Sub: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to publish build event: {e}")

    return {"status": "QUEUED", "request_id": request_id, "execution_mode": execution_mode, **auto_fallback}


@router.post("/api/workloads/{product_id}/retrigger", dependencies=[require(WORKLOAD(manager=True))])
def retrigger_workload_latest(
    product_id: str,
    request: Request,
    body: Optional[Dict[str, Any]] = None,
):
    """
    Retriggers a workload using its most recent feature request or execution run.
    Provides a clean semantic endpoint for callers who do not have an explicit request_id.
    """
    verify_workload_access(product_id, request, require_manager=True)
    if not db:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")

    clean_pid = product_id.strip()

    # 1. Search recent executions for a valid request_id
    try:
        col = db.collection("pipeline_executions")
        try:
            docs = list(col.where("product_id", "==", clean_pid).order_by("started_at", direction=firestore.Query.DESCENDING).limit(5).stream())
        except Exception:
            docs = [d for d in col.where("product_id", "==", clean_pid).stream()]
            docs.sort(key=lambda d: str((d.to_dict() or {}).get("started_at", "")), reverse=True)
            docs = docs[:5]

        for d in docs:
            r_id = (d.to_dict() or {}).get("request_id")
            if r_id:
                return retrigger_feature_request_build(product_id=clean_pid, request_id=r_id, request=request, body=body)
    except HTTPException:
        # FD-48: the inner retrigger's 4xx/5xx is the answer; don't fall through to a different request.
        raise
    except Exception as e:
        logger.warning(f"Could not resolve request_id from executions for {clean_pid}: {e}")

    # 2. Fallback to feature_requests collection
    try:
        fr_col = db.collection("feature_requests")
        try:
            fr_docs = list(fr_col.where("product_id", "==", clean_pid).order_by("created_at", direction=firestore.Query.DESCENDING).limit(1).stream())
        except Exception:
            fr_docs = [d for d in fr_col.where("product_id", "==", clean_pid).stream()]
            fr_docs.sort(key=lambda d: str((d.to_dict() or {}).get("created_at", "")), reverse=True)
            fr_docs = fr_docs[:1]

        if fr_docs:
            return retrigger_feature_request_build(product_id=clean_pid, request_id=fr_docs[0].id, request=request, body=body)
    except HTTPException:
        raise  # FD-48
    except Exception as e:
        logger.warning(f"Could not resolve request_id from feature_requests for {clean_pid}: {e}")

    raise HTTPException(status_code=404, detail=f"No retriggerable feature request specification found for workload '{clean_pid}'")


@router.post("/api/workloads/{product_id}/deploy-infra", response_model=DeployInfraResponse, dependencies=[require(WORKLOAD(manager=True))])
def deploy_workload_infra(
    product_id: str,
    request: Request,
    body: Optional[DeployInfraRequest] = None,
):
    """
    Dedicated Fast-Path IaC Re-Apply endpoint (Zero-LLM, <60s).
    Pulls code from target branch, runs quota/FinOps/AST checks, and dispatches tf-applier.
    Protected by atomic Firestore deployment lock to prevent state lock concurrency collisions.
    """
    verify_workload_access(product_id, request, require_manager=True)
    _refuse_new_run_in_maintenance("infrastructure deploy")  # settings-toggles
    admin_email = getattr(request.state, "user_email", "admin-console")
    main_mod = get_caller_main_module()
    current_project = getattr(main_mod, "project_id", None) or project_id or os.getenv("PROJECT_ID", "")

    if not db:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")

    force = bool(body.force) if body else False
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    # Hardening 5: Atomic Firestore Deployment Lock Guard
    wl_ref = db.collection("workloads").document(product_id)
    wl_doc = wl_ref.get()
    if not wl_doc.exists:
        raise HTTPException(status_code=404, detail=f"Workload '{product_id}' not found")

    wl_data = wl_doc.to_dict() or {}
    _refuse_platform_workload_run(product_id, wl_data, current_project, "Fast-Path re-apply")  # RT14 RT F5
    _refuse_open_express_destroy_refusal(wl_data)   # EXP-7 RT B1 / RT14-07
    dep_lock = wl_data.get("deployment_lock") or {}

    if dep_lock.get("is_locked") and not force:
        locked_at_str = dep_lock.get("locked_at")
        if locked_at_str:
            try:
                locked_dt = datetime.fromisoformat(locked_at_str)
                # 15-minute lock expiration
                if (now - locked_dt).total_seconds() < 900:
                    locked_by = dep_lock.get("locked_by", "another operator")
                    raise HTTPException(
                        status_code=409,
                        detail=f"A deployment is currently in progress for workload '{product_id}' (locked by {locked_by} at {locked_at_str}). Please wait for it to complete or use force=true.",
                    )
            except (ValueError, TypeError):
                pass

    # FD-4N (red-team H1): DEPLOY_ONLY targets (project, repository, branch) come ONLY from the workload doc.
    branch = (wl_data.get("default_branch") or "main").strip()
    requested_branch = (body.branch or "").strip() if body and body.branch else ""
    if requested_branch and requested_branch != branch:
        raise HTTPException(status_code=400, detail=f"branch is fixed to the workload's registered branch '{branch}'.")
    target_project_id = wl_data.get("project_id")
    github_repo = wl_data.get("github_repo")
    if not target_project_id or not github_repo:
        raise HTTPException(status_code=409, detail=f"Workload '{product_id}' has no registered project_id/github_repo.")
    trace_id = f"fastpath-{product_id}-{uuid.uuid4().hex[:6]}"

    # Set deployment lock
    wl_ref.set({
        "deployment_lock": {
            "is_locked": True,
            "locked_at": now_iso,
            "locked_by": admin_email,
            "trace_id": trace_id,
            "branch": branch,
        }
    }, merge=True)

    # Initialize execution tracking document in Firestore
    initial_execution = {
        "trace_id": trace_id,
        "product_id": product_id,
        "feature_title": f"Fast-Path IaC Re-Apply: {product_id}",
        "status": "ACTIVE",
        "current_stage": "TERRAFORM",
        "started_at": now_iso,
        "completed_at": None,
        "elapsed_seconds": 0.0,
        "workflow_execution_id": None,
        "execution_mode": "DEPLOY_ONLY",
        "stages": {
            "discovery": {"status": "SKIPPED", "summary": "Bypassed via Fast-Path"},
            "architect": {"status": "SKIPPED", "summary": "Bypassed via Fast-Path (0 LLM)"},
            "compliance": {"status": "SKIPPED", "summary": "Bypassed via Fast-Path"},
            "vending": {"status": "SKIPPED", "summary": "Brownfield project reused"},
            "developer": {"status": "SKIPPED", "summary": "Bypassed via Zero-Invocation Invariant (Code merged on main)"},
            "qa": {"status": "SKIPPED", "summary": "Bypassed via Fast-Path"},
            "terraform": {"status": "QUEUED", "summary": f"Fast-Path IaC Re-Apply queued (<60s) on branch '{branch}'"},
            "sre": {"status": "QUEUED"},
        },
        "outputs": {
            "github_repo": github_repo,
            "product_id": product_id,
            "target_branch": branch,
            "target_project_id": target_project_id,
            "execution_mode": "DEPLOY_ONLY",
        },
    }
    try:
        db.collection("pipeline_executions").document(trace_id).set(initial_execution)
    except Exception as pe_err:
        logger.warning(f"Could not persist initial pipeline_execution {trace_id}: {pe_err}")

    # Publish to spec-intake-events with execution_mode=DEPLOY_ONLY
    intake_payload = {
        "trace_id": trace_id,
        "product_id": product_id,
        "project_id": target_project_id,
        "target_project_id": target_project_id,
        "github_repo": github_repo,
        "title": f"Fast-Path IaC Re-Apply: {product_id}",
        "spec_text": "Fast-Path IaC re-apply directly to GCP (Zero-LLM deployment bypass).",
        "source_channel": "control_center_deploy_infra",
        "created_at": now_iso,
        "budget_ceiling_monthly_usd": float(wl_data.get("budget_ceiling_monthly_usd", 50.0)),
        "execution_mode": "DEPLOY_ONLY",
        "target_branch": branch,
    }

    # FD deploy-dispatch: the build event is the only thing that starts the re-apply. If it cannot be sent the
    # request fails visibly (typed error_class, classified by which step failed / exception type, never by message
    # text): the execution record is FAILED with that reason and the deployment lock is released at once.
    active_pubsub_getter = getattr(main_mod, "get_pubsub_publisher", get_pubsub_publisher)
    pub_client = active_pubsub_getter()
    if not pub_client or not current_project:
        missing = "Pub/Sub publisher" if not pub_client else "platform project id"
        _fail_deploy_infra_dispatch(
            wl_ref, trace_id, error_class=DEPLOY_DISPATCH_UNAVAILABLE,
            detail=f"Build event not sent: no {missing} is configured on the Control Center.", release_lock=True)
        raise HTTPException(status_code=503, detail={
            "error_class": DEPLOY_DISPATCH_UNAVAILABLE, "trace_id": trace_id,
            "detail": f"Fast-Path re-apply not dispatched: no {missing} is configured."})

    intake_topic = f"projects/{current_project}/topics/spec-intake-events"
    data_bytes = json.dumps(intake_payload).encode("utf-8")
    try:
        future = pub_client.publish(intake_topic, data_bytes)
        msg_id = future.result(timeout=10.0)
    except (TimeoutError, concurrent.futures.TimeoutError) as e:
        # The publisher may still deliver the message after the wait: the outcome is unknown, so the lock is KEPT
        # (released by the workflow's terminal status if it runs, else by the 15-minute expiry) and the record is
        # FAILED with a distinct class (a workflow that does run overwrites it with its own terminal status).
        logger.error(f"Fast-Path deployment event publish timed out for '{product_id}' ({type(e).__name__})")
        _fail_deploy_infra_dispatch(
            wl_ref, trace_id, error_class=DEPLOY_DISPATCH_OUTCOME_UNKNOWN,
            detail="Build event publish timed out; it may still be delivered.", release_lock=False)
        raise HTTPException(status_code=504, detail={
            "error_class": DEPLOY_DISPATCH_OUTCOME_UNKNOWN, "trace_id": trace_id,
            "detail": "Fast-Path re-apply publish timed out; the build event may still be delivered. "
                      "The deployment lock is kept until the re-apply reports back or expires (15 min)."})
    except Exception as e:
        logger.error(f"Failed to publish Fast-Path deployment event for '{product_id}': {type(e).__name__}: {e}")
        _fail_deploy_infra_dispatch(
            wl_ref, trace_id, error_class=DEPLOY_DISPATCH_FAILED,
            detail=f"Build event publish failed ({type(e).__name__}).", release_lock=True)
        raise HTTPException(status_code=502, detail={
            "error_class": DEPLOY_DISPATCH_FAILED, "trace_id": trace_id,
            "detail": f"Fast-Path re-apply not dispatched: publish failed ({type(e).__name__})."})

    logger.info(f"Dispatched Fast-Path IaC Re-Apply to Pub/Sub for '{product_id}' (Msg ID: {msg_id}) by {admin_email}")
    return DeployInfraResponse(
        status="DISPATCHED",
        product_id=product_id,
        execution_mode="DEPLOY_ONLY",
        branch=branch,
        trace_id=trace_id,
        pubsub_message_id=msg_id,
        execution=initial_execution,
    )


# STALE-RUN-AUTOFAIL-BOUND (RT F5): a retrigger whose build event was definitely not published. Its run record is
# written before the publish, so it is closed here (typed) instead of staying ACTIVE with nothing behind it.
RETRIGGER_DISPATCH_FAILED = "RETRIGGER_DISPATCH_FAILED"
# Red-team delta D1: the publish wait timed out; the event may still be delivered (the run record stays ACTIVE).
RETRIGGER_DISPATCH_OUTCOME_UNKNOWN = "RETRIGGER_DISPATCH_OUTCOME_UNKNOWN"


def _fail_retrigger_dispatch(trace_id: str, err: Exception) -> None:
    failed_at = datetime.now(timezone.utc).isoformat()
    try:
        db.collection("pipeline_executions").document(trace_id).set({
            "status": "FAILED",
            "current_stage": "FAILED",
            "error_class": RETRIGGER_DISPATCH_FAILED,
            "error": f"Build event publish failed ({type(err).__name__}); no workflow was started.",
            "completed_at": failed_at,
        }, merge=True)
    except Exception as pe_err:
        logger.error(f"Could not record the failed retrigger dispatch on {trace_id}: {type(pe_err).__name__}")


# FD deploy-dispatch: typed reasons for a Fast-Path re-apply whose build event was not (or maybe not) sent.
DEPLOY_DISPATCH_UNAVAILABLE = "DEPLOY_DISPATCH_UNAVAILABLE"
DEPLOY_DISPATCH_FAILED = "DEPLOY_DISPATCH_FAILED"
DEPLOY_DISPATCH_OUTCOME_UNKNOWN = "DEPLOY_DISPATCH_OUTCOME_UNKNOWN"


def _fail_deploy_infra_dispatch(wl_ref, trace_id: str, *, error_class: str, detail: str,
                                release_lock: bool) -> None:
    """Records a re-apply that never started: execution FAILED (typed), and (unless the outcome is unknown) the
    deployment lock this request took is released. Best effort: a store error is logged, never masks the response."""
    failed_at = datetime.now(timezone.utc).isoformat()
    try:
        db.collection("pipeline_executions").document(trace_id).set({
            "status": "FAILED",
            "current_stage": "FAILED",
            "error_class": error_class,
            "failed_stage": "terraform",
            "error": detail,
            "completed_at": failed_at,
            "stages": {
                "terraform": {"status": "FAILED", "error_class": error_class, "summary": detail,
                              "completed_at": failed_at},
                "sre": {"status": "SKIPPED", "summary": "Skipped: the re-apply was not dispatched"},
            },
        }, merge=True)
    except Exception as pe_err:
        logger.error(f"Could not record failed Fast-Path dispatch on {trace_id}: {type(pe_err).__name__}")
    if not release_lock:
        return
    try:
        snap = wl_ref.get()
        lock = dict(((snap.to_dict() or {}) if snap.exists else {}).get("deployment_lock") or {})
        if lock.get("trace_id") != trace_id:
            return  # a forced re-apply took the lock since: it is not ours to release
        lock.update({"is_locked": False, "released_at": failed_at, "release_reason": error_class})
        # Same version-checked write as the gateway release: a re-apply that locks in between wins.
        wl_ref.update({"deployment_lock": lock}, option=db.write_option(last_update_time=snap.update_time))
    except Exception as lock_err:
        logger.error(f"Could not release deployment lock for {trace_id}: {type(lock_err).__name__} "
                     f"(it expires after 15 minutes)")


@router.post("/api/workloads/{product_id}/deployment-lock/unlock", dependencies=[require(WORKLOAD(manager=True))])
def release_workload_deployment_lock(product_id: str, request: Request):
    """Operator manual override to release a stuck deployment lock."""
    verify_workload_access(product_id, request, require_manager=True)
    admin_email = getattr(request.state, "user_email", "admin-console")
    if not db:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")

    wl_ref = db.collection("workloads").document(product_id)
    wl_ref.set({
        "deployment_lock": {
            "is_locked": False,
            "unlocked_at": datetime.now(timezone.utc).isoformat(),
            "unlocked_by": admin_email,
        }
    }, merge=True)
    logger.info(f"Deployment lock released for '{product_id}' by {admin_email}")
    return {"status": "SUCCESS", "product_id": product_id, "is_locked": False}



@router.post("/api/workloads/{product_id}/executions/{trace_id}/resume-cooldown", dependencies=[require(WORKLOAD_CHILD("trace_id", "pipeline_executions", manager=True))])
def resume_execution_cooldown(product_id: str, trace_id: str, request: Request):
    """
    Operator manual override: unpauses a 429 rate-limit cooldown immediately,
    releasing the agent from its sleep loop to retry Gemini invocation.
    """
    verify_workload_access(product_id, request, require_manager=True)
    if not db:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")

    doc_ref = db.collection("pipeline_executions").document(trace_id)
    doc = doc_ref.get()
    # FD-4N (red-team B1): the execution must belong to this workload (exact product_id match).
    if not doc.exists or (doc.to_dict() or {}).get("product_id") != product_id:
        raise HTTPException(status_code=404, detail="Pipeline execution not found")

    now_iso = datetime.now(timezone.utc).isoformat()
    doc_ref.set(
        {
            "force_resume": True,
            "status": "RUNNING",
            "updated_at": now_iso,
            "cooldown_state": {
                "is_paused": False,
                "resumed_early": True,
                "resumed_at": now_iso,
            },
        },
        merge=True,
    )
    logger.info(f"Operator released rate-limit cooldown early for trace {trace_id} ({product_id})")
    return {"status": "SUCCESS", "message": "Rate-limit cooldown released early. Agent resuming execution."}


@router.post("/api/workloads/{product_id}/budget", dependencies=[require(ADMIN)])
def update_workload_budget(product_id: str, req: UpdateBudgetRequest, request: Request):
    """Dynamically updates the monthly budget ceiling for a specific workload in Firestore."""
    verify_admin_access(request)

    if db:
        try:
            db.collection("workloads").document(product_id).set(
                {"budget_ceiling_monthly_usd": req.budget_ceiling_monthly_usd},
                merge=True,
            )
            logger.info(f"Updated budget ceiling for {product_id} to ${req.budget_ceiling_monthly_usd:.2f}/mo by {getattr(request.state, 'user_email', 'unknown')}")
            return {"status": "UPDATED", "product_id": product_id, "new_budget": req.budget_ceiling_monthly_usd}
        except Exception as e:
            logger.warning(f"Could not persist budget update to Firestore: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to persist budget update: {e}")

    raise HTTPException(status_code=503, detail="Firestore database unavailable")


@router.get("/api/workloads/{product_id}/policies", dependencies=[require(WORKLOAD())])
def get_workload_policies(product_id: str):
    """Retrieves workload governance and code freeze policies from Firestore."""
    if db:
        try:
            doc = db.collection("workloads").document(product_id).get()
            if doc.exists:
                data = doc.to_dict() or {}
                return {
                    "product_id": product_id,
                    "code_freeze": bool(data.get("code_freeze", False)),
                    "sre_auto_healing_enabled": bool(data.get("sre_auto_healing_enabled", True)),
                    "refactor_scanner_enabled": bool(data.get("refactor_scanner_enabled", True)),
                    "require_human_code_review": bool(data.get("require_human_code_review", True)),
                    "require_plan_approval": bool(data.get("require_plan_approval", False)),
                }
        except Exception as e:
            logger.warning(f"Could not read policies for {product_id}: {e}")

    return {
        "product_id": product_id,
        "code_freeze": False,
        "sre_auto_healing_enabled": True,
        "refactor_scanner_enabled": True,
        "require_human_code_review": True,
        "require_plan_approval": False,
    }


@router.patch("/api/workloads/{product_id}/policies", dependencies=[require(ADMIN)])
def update_workload_policies(product_id: str, req: UpdateWorkloadPoliciesRequest, request: Request):
    """
    Dynamically updates workload governance policies (master code freeze, SRE auto-healing, refactor scanner, human code review, plan approval)
    in Firestore. Changes take effect across all autonomous agents immediately.
    """
    verify_admin_access(request)

    update_dict = {}
    if req.code_freeze is not None:
        update_dict["code_freeze"] = req.code_freeze
    if req.sre_auto_healing_enabled is not None:
        update_dict["sre_auto_healing_enabled"] = req.sre_auto_healing_enabled
    if req.refactor_scanner_enabled is not None:
        update_dict["refactor_scanner_enabled"] = req.refactor_scanner_enabled
    if req.require_human_code_review is not None:
        update_dict["require_human_code_review"] = req.require_human_code_review
        update_dict["auto_merge"] = not req.require_human_code_review
    elif req.auto_merge is not None:
        update_dict["auto_merge"] = req.auto_merge
        update_dict["require_human_code_review"] = not req.auto_merge
    if req.require_plan_approval is not None:
        update_dict["require_plan_approval"] = req.require_plan_approval
    if req.budget_breach_policy is not None:
        policy_val = req.budget_breach_policy.value if hasattr(req.budget_breach_policy, "value") else str(req.budget_breach_policy)
        update_dict["budget_breach_policy"] = policy_val

    if not update_dict:
        return {"status": "NOOP", "product_id": product_id}

    if db:
        try:
            db.collection("workloads").document(product_id).set(update_dict, merge=True)
            logger.info(f"Updated governance policies for {product_id}: {update_dict} by {getattr(request.state, 'user_email', 'unknown')}")
            return {
                "status": "UPDATED",
                "product_id": product_id,
                "policies": update_dict,
                "message": f"Updated governance policies for {product_id}",
            }
        except Exception as e:
            logger.warning(f"Could not persist policy update to Firestore: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to persist policy update: {e}")

    raise HTTPException(status_code=503, detail="Firestore database unavailable")


@router.patch("/api/workloads/{product_id}/github-actions-deploy", dependencies=[require(ADMIN)])
def update_workload_github_actions_deploy(product_id: str, req: UpdateGitHubActionsDeployRequest, request: Request):
    """GHA-DEPLOY-SWITCH (register row GHA-DEPLOY-SWITCH): turn the workload's GitHub Actions deploy path on or off.
    Administrator only; GitHub workloads only (422 GHA_DEPLOY_SWITCH_NOT_GITHUB for Serverless Git); 404 for an
    unknown workload; 503 when the store cannot be read or written. The new value and the previous one are written
    with an audit entry in one batch.

    Effect: the switch is read at every developer run and every deploy. Off: the next pipeline run commits no deploy
    workflow and deletes the existing `.github/workflows/deploy-*.yml`; the next deploy destroys the workload's WIF
    pool, provider and `sa-gh-deployer` (the pool id stays reserved by Google for 30 days). A deploy of IaC that was
    generated while the switch was on stops for an operator with APPLY.GHA_DEPLOY_SWITCH_NOT_IN_IAC (operator_required:
    no automatic developer run) until the workload's next pipeline run regenerates it. On: the next pipeline run writes the workflows again and the next deploy recreates the resources."""
    verify_admin_access(request)
    operator = getattr(request.state, "user_email", None) or "unknown"
    clean_pid = product_id.strip().lower()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")
    if github_actions_deploy_enabled is None:
        raise HTTPException(status_code=503, detail="GHA_DEPLOY_SWITCH_UNAVAILABLE: shared.github_identity is not "
                                                    "available in this service")
    doc_ref = db.collection("workloads").document(clean_pid)
    try:
        snap = doc_ref.get()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"workloads/{clean_pid} unreadable ({type(e).__name__})")
    if not getattr(snap, "exists", False):
        raise HTTPException(status_code=404, detail=f"Workload '{clean_pid}' not found.")
    current = snap.to_dict() or {}
    vcs = str(current.get("vcs_provider") or "GITHUB").strip().upper()
    if vcs == "SERVERLESS_GIT":
        raise HTTPException(status_code=422, detail={
            "error_class": "GHA_DEPLOY_SWITCH_NOT_GITHUB",
            "detail": f"Workload '{clean_pid}' uses Serverless Git; the GitHub Actions deploy switch does not apply."})
    previous = current.get(GITHUB_ACTIONS_DEPLOY_FIELD)
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        batch = db.batch()
        batch.update(doc_ref, {GITHUB_ACTIONS_DEPLOY_FIELD: bool(req.enabled),
                               "github_actions_deploy_updated_at": now_iso,
                               "github_actions_deploy_updated_by": operator})
        batch.set(doc_ref.collection("audit_logs").document(), {
            "action": "GITHUB_ACTIONS_DEPLOY_CHANGED",
            "operator_email": operator,
            "timestamp": now_iso,
            "previous": previous,
            "new": bool(req.enabled),
        })
        batch.commit()
    except Exception as e:  # noqa: BLE001
        logger.error(f"GitHub Actions deploy switch of '{clean_pid}' not written: {type(e).__name__}: {e}")
        raise HTTPException(status_code=503, detail=f"GHA_DEPLOY_SWITCH_NOT_WRITTEN: {type(e).__name__}")
    logger.info(f"GHA-DEPLOY-SWITCH: '{clean_pid}' github_actions_deploy {previous!r} -> {bool(req.enabled)} "
                f"by {operator}")
    return {
        "status": "UPDATED",
        "product_id": clean_pid,
        "github_actions_deploy": bool(req.enabled),
        "previous": previous,
        "message": ("GitHub Actions deploy is on: the next pipeline run writes the deploy workflows and the next deploy "
                    "creates the workload's identity federation and deployer account." if req.enabled else
                    "GitHub Actions deploy is off: the next pipeline run regenerates the workload's infrastructure "
                    "code and deletes the deploy workflows, and its deploy removes the workload's identity federation "
                    "pool, provider and deployer account. Until that pipeline run, a deploy of the current code stops "
                    "for an operator (APPLY.GHA_DEPLOY_SWITCH_NOT_IN_IAC). Every deploy then goes through StackVend's "
                    "pipeline."),
    }


@router.get("/api/workloads/{product_id}/access", dependencies=[require(ADMIN)])
def get_workload_access(product_id: str, request: Request):
    """FD-4DT: the workload's current access record, read only, for the Control Center's access-editing screen.
    Administrator only, like the PATCH below (the workload details answer does not carry the record).

    ``access`` is the stored ``workloads/{pid}.access`` exactly as written (``None`` when there is none);
    ``access_valid`` says whether it is a valid record (``stored_access_policy``); ``access_widening_pending`` is True
    while a confirmed widening waits for its plan approval (the flag is present and non-null, the gateway's rule).
    Writes nothing: 503 when the store is unavailable or the read fails, 404 for an unknown workload."""
    verify_admin_access(request)
    clean_pid = product_id.strip().lower()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")
    try:
        snap = db.collection("workloads").document(clean_pid).get()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"workloads/{clean_pid} unreadable ({type(e).__name__})")
    if not getattr(snap, "exists", False):
        raise HTTPException(status_code=404, detail=f"Workload '{clean_pid}' not found.")
    current = snap.to_dict() or {}
    record = current.get("access")
    return {
        "product_id": clean_pid,
        "access": record,
        "access_valid": record is not None and stored_access_policy(record) is not None,
        "access_updated_at": current.get("access_updated_at"),
        "access_updated_by": current.get("access_updated_by"),
        "access_widening_pending": current.get(ACCESS_WIDENING_APPROVAL_FIELD) is not None,
    }


@router.patch("/api/workloads/{product_id}/access", dependencies=[require(ADMIN)])
def update_workload_access(product_id: str, req: UpdateWorkloadAccessRequest, request: Request):
    """Lane 19 L19-11: set the workload's access record (``workloads/{pid}.access``). Administrator only.

    This is the operator's answer to a build stopped with ``ACCESS_POLICY_INCOMPLETE`` / ``ACCESS_POLICY_REQUIRED``
    and the backfill tool for existing workloads (``source="migration"``). The body is validated by the same model as
    the create form (exact principals, A8 answer for PUBLIC_APP, at least one principal for a private mode; 422
    otherwise). The record replaces the previous one whole (no merge), and every change is written to the workload's
    audit trail with the previous and new record. The next build or retrigger uses it.

    L19-F4 (owner decision): a WIDENING (``shared.access_policy.widening_changes``: a less restrictive mode, a member
    that was not in the previous private record, or no valid previous record) needs ``confirm_widening: true``;
    without it the answer is 422 ``ACCESS_WIDENING_UNCONFIRMED`` and nothing is written. A confirmed widening is
    audited with ``widening: true`` and, in the same atomic batch, sets the one-shot
    ``workloads/{pid}.access_widening_approval`` flag, which forces plan approval on the workload's next run (the
    gateway's pre-build gate, reason ``ACCESS_WIDENED``; cleared only by that approval). A narrowing or unchanged
    record needs no confirmation and leaves any pending flag in place."""
    verify_admin_access(request)
    operator = getattr(request.state, "user_email", None) or "unknown"
    clean_pid = product_id.strip().lower()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")

    policy = req.to_policy(req.source)
    record = access_record(policy)
    doc_ref = db.collection("workloads").document(clean_pid)
    try:
        snap = doc_ref.get()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"workloads/{clean_pid} unreadable ({type(e).__name__})")
    if not getattr(snap, "exists", False):
        raise HTTPException(status_code=404, detail=f"Workload '{clean_pid}' not found.")
    current = snap.to_dict() or {}
    previous = current.get("access")
    changes = access_widening(previous, policy)
    widening = bool(changes)
    previous_mode = (previous.get("mode") if isinstance(previous, dict)
                     and WideningChange.NO_PREVIOUS_RECORD.value not in changes else None)
    if widening and req.confirm_widening is not True:
        raise HTTPException(status_code=422, detail={
            "error_class": "ACCESS_WIDENING_UNCONFIRMED",
            "changes": changes,
            "previous_mode": previous_mode,
            "new_mode": record["mode"],
            "summary": "This record widens who may use the workload; send it again with confirm_widening=true. "
                       "The change is audited and the workload's next run waits for plan approval.",
        })
    now_iso = datetime.now(timezone.utc).isoformat()
    from google.api_core import exceptions as gexc

    try:
        # One atomic batch: the record, its audit entry and (for a widening) the one-shot plan-approval flag land
        # together or not at all. update() replaces the `access` map whole, so a narrower record never keeps a wider
        # record's leftovers. A narrowing never touches a pending flag (an unapproved widening stays unapproved).
        # RT R4: the update carries a precondition on the version read above, so the widening decision is never made
        # on a stale record (a concurrent PATCH -> 409, nothing written).
        batch = db.batch()
        audit_ref = doc_ref.collection("audit_logs").document()
        doc_update = {"access": record, "access_updated_at": now_iso, "access_updated_by": operator}
        flag = None
        if widening:
            # RT R2: "last approved -> now" (a still-pending flag keeps its earliest baseline) with the exact members
            # added, so the plan approver sees what is widened.
            flag = widening_approval(
                previous=stored_access_policy(previous), new=policy,
                changes=[WideningChange(c) for c in changes], pending=current.get(ACCESS_WIDENING_APPROVAL_FIELD),
                audit_log_id=audit_ref.id, set_at=now_iso, set_by=operator).model_dump(mode="json")
            doc_update[ACCESS_WIDENING_APPROVAL_FIELD] = flag
        batch.update(doc_ref, doc_update, option=db.write_option(last_update_time=snap.update_time))
        batch.set(audit_ref, {
            "action": "WORKLOAD_ACCESS_SET",
            "operator_email": operator,
            "timestamp": now_iso,
            "source": req.source,
            "reason": req.reason or "",
            "previous_access": previous if isinstance(previous, dict) else None,
            "new_access": record,
            "widening": widening,
            "widening_changes": changes,
            "plan_approval_forced": widening,
            "widening_approval": flag,
        })
        batch.commit()
    except gexc.FailedPrecondition:
        raise HTTPException(status_code=409, detail=f"workloads/{clean_pid} changed since it was read; "
                                                    "send the PATCH again (nothing was written).")
    except Exception as e:  # noqa: BLE001
        logger.error(f"Failed to set the access record of '{clean_pid}': {e}")
        raise HTTPException(status_code=500, detail=f"Failed to persist the access record: {type(e).__name__}")
    logger.info(f"Access record of '{clean_pid}' set to {record['mode']} "
                f"({len(record['invoker_principals'])} principal(s), source {req.source}, widening {widening}) "
                f"by {operator}")
    return {"status": "UPDATED", "product_id": clean_pid, "access": record, "widening": widening,
            "widening_changes": changes, "plan_approval_forced": widening}


@router.post("/api/workloads/{product_id}/decommission", response_model=DecommissionResponse, dependencies=[require(ADMIN)])
def decommission_workload_endpoint(product_id: str, req: DecommissionRequest, request: Request):
    verify_admin_access(request)
    """
    Decommissions a child workload to zero cloud spend (lane 18 S2: executed ONLY by project-vending):
    1. ADMIN route; platform workloads refused (HTTP 400); the workload record must be readable (404 / 503)
    2. High-friction safeguard: req.confirm_product_id must equal the workload id (HTTP 422)
    3. Mints a single-use 15-minute PROJECT_DECOMMISSION approval for this human ADMIN session (principal_type from
       the auth layer) naming the ledger's project id and number
    4. Calls project-vending /projects/{id}/decommission with the CC's ID token. Vending runs the destructive guard,
       deletes the project by number, archives state, frees IPAM and marks the ledger DECOMMISSIONED.
       Any non-200 answer -> HTTP 502 with vending's {code, detail}; the CC changes nothing in the ledger.
       A refused approval mint keeps its own status (401/403/409/503) with the same typed {code, detail} body.
    5. On success: sandbox display status, HITL audit record, cascade-cancel of active pipeline executions.
    There is no in-process CRM fallback (removed: it released every lien and deleted by id).
    """
    admin_email = getattr(request.state, "user_email", "admin-console")
    clean_pid = product_id.strip().lower()

    # 1. Platform self-preservation guard
    platform_ids = {
        os.getenv("PROJECT_ID", "").strip(),
        os.getenv("PLATFORM_PROJECT_ID", "").strip(),
        "project-stackvend",
        "stackvend",
        "project-castor",
        "castor-platform",
        "castor",
        "platform",
    } - {""}
    if clean_pid in platform_ids:
        raise HTTPException(status_code=400, detail="Core platform workload cannot be decommissioned.")

    if not db:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")
    try:
        doc = db.collection("workloads").document(clean_pid).get()
    except Exception as e:  # noqa: BLE001 - lane 18 S2: a ledger read error refuses (no guessing the target)
        logger.error(f"Could not read workload doc for '{clean_pid}': {e}")
        raise HTTPException(status_code=503, detail=f"Could not read workload '{clean_pid}'; nothing was changed.")
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Workload '{clean_pid}' not found.")
    workload_data = doc.to_dict() or {}
    if workload_data.get("is_castor") is True:
        raise HTTPException(status_code=400, detail="Core platform workload cannot be decommissioned.")

    target = destructive_actions.resolve_target(clean_pid, workload_data)
    target_project_id = target["project_id"]
    if target_project_id in platform_ids or target_project_id.startswith("castor-platform"):
        raise HTTPException(status_code=400, detail=f"Cannot decommission protected platform project '{target_project_id}'.")

    # 2. High-friction confirmation verification
    if req.confirm_product_id.strip() != clean_pid:
        raise HTTPException(
            status_code=422,
            detail=f"Safety verification failed: Confirmation input '{req.confirm_product_id}' does not match workload ID '{clean_pid}'.",
        )

    # 3. Mint the approval for exactly this action and target. Without a ledger project id + number nothing is minted:
    # vending then reports the exact reason (e.g. LEDGER_UNPROVENANCED) and refuses.
    approval_id = None
    if target_project_id and target["project_number"]:
        try:
            approval_id = destructive_actions.mint_approval(
                request, action=destructive_actions.PROJECT_DECOMMISSION, product_id=clean_pid,
                project_id=target_project_id, project_number=target["project_number"],
                reason=req.reason or "Manual Admin Decommission via Control Center",
                **({"delete_without_archive": True} if req.delete_without_archive is True else {}))
        except destructive_actions.MintRefused as refused:
            return destructive_actions.refusal_response(refused)

    # 4. Vending executes (or refuses). No fallback.
    vending_body = {"action_class": destructive_actions.PROJECT_DECOMMISSION, "approval_id": approval_id,
                    "operator_email": admin_email}
    if req.delete_without_archive is True:
        vending_body["delete_without_archive"] = True   # FD-7L plan 2.8 (vending checks the approval carries it)
    outcome = destructive_actions.call_vending(
        make_vending_request, f"/projects/{clean_pid}/decommission", vending_body,
        request=request, timeout=destructive_actions.DECOMMISSION_TIMEOUT_SECONDS)
    if not outcome.ok:
        destructive_actions.void_approval(approval_id, outcome)
        if not outcome.http_status:
            # RT H4: no answer is not proof of failure; vending may have finished after the CC stopped waiting.
            try:
                after = db.collection("workloads").document(clean_pid).get()
                if (after.to_dict() or {}).get("status") == "DECOMMISSIONED":
                    outcome.detail += (" (the ledger now shows DECOMMISSIONED: vending finished after the Control "
                                       "Center stopped waiting; reload the page)")
            except Exception as re_err:  # noqa: BLE001 - the 502 below is reported either way
                logger.warning(f"Could not re-read workload '{clean_pid}' after a vending timeout: {re_err}")
        return destructive_actions.failure_response(outcome, action="Decommission", product_id=clean_pid)
    vended = outcome.body
    logger.info(f"Vending decommissioned '{clean_pid}': {vended.get('crm_operation')}")

    # 5. CC-side follow-ups (the ledger status, spend, state archive and IPAM were written by vending)
    now_iso = vended.get("decommissioned_at") or datetime.now(timezone.utc).isoformat()
    deleted_project_id = vended.get("deleted_project_id") or target_project_id
    cascade_failures: List[Dict[str, Any]] = []  # SAT-43: runs whose workflow execution could not be cancelled
    try:
        doc_ref = db.collection("workloads").document(clean_pid)
        if workload_data.get("is_sandbox"):
            doc_ref.set({"sandbox_decommission_status": "DECOMMISSIONED"}, merge=True)
        doc_ref.collection("audit_logs").document().set({
            "action": "HITL_MANUAL_APPROVED_DECOMMISSION",
            "operator_email": admin_email,
            "deleted_project_id": deleted_project_id,
            "deleted_project_number": vended.get("deleted_project_number"),
            "crm_operation": vended.get("crm_operation"),
            "reason": req.reason or "Manual Admin Decommission via Control Center",
            "timestamp": now_iso,
            "approval_id": approval_id,
            "client_approval_reference": req.approval_id,
            "executed_by": "project-vending",
        })
        logger.info(f"Recorded HITL_MANUAL_APPROVED_DECOMMISSION for '{clean_pid}' by {admin_email}")

        # Cascade decommission to any active/running pipeline executions to eliminate phantom executions
        aborted_runs = cancel_workload_active_executions(
            target_product_id=clean_pid,
            operator_email=admin_email,
            reason=f"Parent workload '{clean_pid}' was manually decommissioned",
            failures=cascade_failures,
        )
        if aborted_runs > 0:
            logger.info(f"Decommission cascade aborted {aborted_runs} active execution(s) for '{clean_pid}'")
    except Exception as fs_err:  # noqa: BLE001 - the project is already deleted; never hide that
        logger.warning(f"Post-decommission Firestore notice for '{clean_pid}': {fs_err}")

    warnings = list(vended.get("warnings") or [])
    if cascade_failures:
        warnings.append(_cascade_failure_note(cascade_failures))
    return DecommissionResponse(
        status="DECOMMISSIONED",
        product_id=clean_pid,
        deleted_project_id=deleted_project_id,
        decommissioned_at=now_iso,
        decommissioned_by=vended.get("decommissioned_by") or admin_email,
        last_active_project_id=deleted_project_id,
        message=(vended.get("message") or f"Workload '{clean_pid}' decommissioned; GitHub repository and Firestore "
                 "specifications preserved.") + (f" Warnings: {'; '.join(map(str, warnings))}" if warnings else ""),
        workflow_cancel_failures=cascade_failures,
    )


# FD vending-redeploy: typed reasons the CC redeploy answers with when the vending service did not answer HTTP 200.
# A typed REDEPLOY_* error_class from the vending service (see apps/project-vending/vending.py) is passed through.
REDEPLOY_VENDING_UNAVAILABLE = "REDEPLOY_VENDING_UNAVAILABLE"  # no vending service configured: nothing ran
REDEPLOY_VENDING_CALL_FAILED = "REDEPLOY_VENDING_CALL_FAILED"  # the call failed without an answer
REDEPLOY_OUTCOME_UNKNOWN = "REDEPLOY_OUTCOME_UNKNOWN"          # no answer in time: vending records the outcome
REDEPLOY_FAILED = "REDEPLOY_FAILED"                            # a non-200 answer without a typed error_class


@router.post("/api/workloads/{product_id}/redeploy", response_model=RedeployResponse, dependencies=[require(ADMIN)])
def redeploy_workload_endpoint(
    product_id: str,
    request: Request,
    payload: Optional[RedeployRequestWithFolder] = None,
):
    verify_admin_access(request)
    _refuse_new_run_in_maintenance("redeploy")  # settings-toggles
    """
    Redeploys a decommissioned workload into a fresh Google Cloud child project:
    1. Validates user authentication
    2. Checks that the workload is in DECOMMISSIONED status
    3. Calls Vending Service to vend a new project (with optional target_folder_id), rebind GitHub WIF secrets, and apply Terraform
    4. Updates status back to ACTIVE with new live service_url, only when vending answered HTTP 200 (FD vending-redeploy)
    """
    admin_email = getattr(request.state, "user_email", "admin-console")
    clean_pid = product_id.strip().lower()
    now_iso = datetime.now(timezone.utc).isoformat()
    target_folder_id = payload.target_folder_id if payload else None

    workload_data = {}
    if db:
        try:
            doc = db.collection("workloads").document(clean_pid).get()
            if not doc.exists:
                raise HTTPException(status_code=404, detail=f"Workload '{clean_pid}' not found.")
            workload_data = doc.to_dict() or {}
        except Exception as e:
            if hasattr(e, "status_code"):
                raise
            logger.warning(f"Could not read workload doc for '{clean_pid}': {e}")

    current_status = workload_data.get("status")
    if current_status and current_status != "DECOMMISSIONED":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot redeploy workload '{clean_pid}': current status is '{current_status}'. Only DECOMMISSIONED workloads can be redeployed.",
        )

    # Call the vending service. It resolves the terraform service itself (env, else Cloud Run lookup) and ignores
    # any URL in the body, so none is sent (security: vending's ID token only ever goes to its own resolved URL).
    v_body = {"operator_email": admin_email}
    if target_folder_id:
        v_body["target_folder_id"] = target_folder_id
    # FD vending-redeploy: the workload is ACTIVE only when the vending service answered HTTP 200 (it answers 200
    # only when the terraform deploy did). Any other outcome writes nothing here: the vending service has already
    # recorded the typed FAILED reason (or, when it never ran, the workload is still DECOMMISSIONED), and the
    # response carries a typed error_class (classified by HTTP status / exception type, never by message text).
    import httpx

    try:
        resp = make_vending_request(
            method="POST",
            path=f"/projects/{clean_pid}/redeploy",
            json_body=v_body,
            timeout=180.0,
            request=request,
        )
    except (httpx.ConnectTimeout, httpx.PoolTimeout) as v_err:
        # RT S3: the request was never sent.
        logger.warning(f"Vending redeploy call for '{clean_pid}' not sent ({type(v_err).__name__})")
        raise HTTPException(status_code=502, detail={
            "error_class": REDEPLOY_VENDING_CALL_FAILED, "product_id": clean_pid,
            "detail": f"The vending service could not be reached ({type(v_err).__name__}); nothing was redeployed."})
    except httpx.TimeoutException as v_err:
        logger.warning(f"Vending redeploy of '{clean_pid}' did not answer within 180 s ({type(v_err).__name__})")
        raise HTTPException(status_code=504, detail={
            "error_class": REDEPLOY_OUTCOME_UNKNOWN, "product_id": clean_pid,
            "detail": "The redeploy is still running or its outcome is unknown; the vending service records the "
                      "final status (ACTIVE or FAILED) on the workload."})
    except Exception as v_err:
        logger.warning(f"Vending redeploy call for '{clean_pid}' failed ({type(v_err).__name__}: {v_err})")
        raise HTTPException(status_code=502, detail={
            "error_class": REDEPLOY_VENDING_CALL_FAILED, "product_id": clean_pid,
            "detail": f"The vending service could not be reached ({type(v_err).__name__}); nothing was redeployed."})
    if resp is None:
        raise HTTPException(status_code=503, detail={
            "error_class": REDEPLOY_VENDING_UNAVAILABLE, "product_id": clean_pid,
            "detail": "No vending service is configured; nothing was redeployed."})
    if resp.status_code != 200:
        try:
            v_detail = resp.json().get("detail")
        except Exception:
            v_detail = None
        logger.warning(f"Vending service redeploy of '{clean_pid}' answered HTTP {resp.status_code}")
        if isinstance(v_detail, dict) and _is_error_class(v_detail.get("error_class")):
            detail = dict(v_detail)  # the vending service's typed failure (REDEPLOY_*), passed through
        else:
            detail = {"error_class": REDEPLOY_FAILED, "product_id": clean_pid, "http_status": resp.status_code,
                      "detail": v_detail if isinstance(v_detail, str) else f"Vending service HTTP {resp.status_code}"}
        # RT low: an untyped upstream 401/403 is the CC's own identity being refused by vending, not the operator's
        # authorization: answer 502 so the browser does not read it as its own authz failure.
        if not (400 <= resp.status_code < 600) or (detail["error_class"] == REDEPLOY_FAILED
                                                   and resp.status_code in (401, 403)):
            out_status = 502
        else:
            out_status = resp.status_code
        raise HTTPException(status_code=out_status, detail=detail)
    # RT R2: project id and URL come only from vending's 200 body (vending already recorded them); nothing is invented.
    try:
        data = resp.json() or {}
    except Exception as parse_err:
        logger.warning(f"Vending redeploy of '{clean_pid}' answered 200 with an unreadable body ({type(parse_err).__name__})")
        data = {}
    if not isinstance(data, dict):
        data = {}
    new_project_id = data.get("project_id") if isinstance(data.get("project_id"), str) and data.get("project_id") else None
    new_service_url = data.get("service_url") if isinstance(data.get("service_url"), str) and data.get("service_url") else None
    # RT14-18: vending's typed reason the GitHub Actions deploy secrets were not written, passed through as reported.
    wif_secrets_error = data.get("wif_secrets_error") if isinstance(data.get("wif_secrets_error"), dict) else None
    if wif_secrets_error:
        logger.error(f"Redeploy of '{clean_pid}': GitHub Actions deploy secrets not written "
                     f"({wif_secrets_error.get('error_class')})")
    logger.info(f"Vending service redeployed '{clean_pid}' into '{new_project_id}'")

    # Update Firestore
    if db:
        try:
            doc_ref = db.collection("workloads").document(clean_pid)
            update_data = {
                "status": "ACTIVE",
                "redeployed_at": now_iso,
                "redeployed_by": admin_email,
                "spend_last_updated_at": now_iso,
            }
            # Only values vending reported: a missing one leaves vending's own record as it is.
            if new_project_id:
                update_data["project_id"] = new_project_id
            if new_service_url:
                update_data["service_url"] = new_service_url
            if target_folder_id:
                update_data["folder_id"] = target_folder_id
            doc_ref.set(update_data, merge=True)

            audit_ref = doc_ref.collection("audit_logs").document()
            audit_ref.set({
                "action": "WORKLOAD_REDEPLOYED",
                "operator_email": admin_email,
                "new_project_id": new_project_id,
                "service_url": new_service_url,
                "target_folder_id": target_folder_id,
                "timestamp": now_iso,
            })
            logger.info(f"Updated Firestore status for '{clean_pid}' to ACTIVE (New project: {new_project_id})")
        except Exception as fs_err:
            logger.warning(f"Firestore redeploy update notice for '{clean_pid}': {fs_err}")

    return RedeployResponse(
        status="ACTIVE",
        product_id=clean_pid,
        new_project_id=new_project_id,
        service_url=new_service_url,
        redeployed_at=now_iso,
        redeployed_by=admin_email,
        message=f"Workload '{clean_pid}' successfully redeployed into fresh project '{new_project_id}'. "
                f"Live URL: {new_service_url or 'not reported'}"
                + (f" GitHub Actions deploy secrets were NOT written ({wif_secrets_error.get('error_class')})."
                   if wif_secrets_error else ""),
        wif_secrets_error=wif_secrets_error,
    )


@router.post("/api/workloads/{product_id}/archive", response_model=ArchiveWorkloadResponse, dependencies=[require(ADMIN)])
def archive_workload_endpoint(product_id: str, request: Request):
    verify_admin_access(request)
    """
    Archives a decommissioned workload:
    1. Validates admin authentication.
    2. Guard: Only workloads currently in DECOMMISSIONED status can be archived.
    3. Updates Firestore status to 'ARCHIVED' and records archived_at and archived_by.
    4. Writes an audit record to the workload's audit trail.
    """
    admin_email = getattr(request.state, "user_email", "admin-console")
    clean_pid = product_id.strip().lower()

    if not db:
        raise HTTPException(status_code=500, detail="Database client is unavailable.")

    doc_ref = db.collection("workloads").document(clean_pid)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Workload '{clean_pid}' not found.")

    workload_data = doc.to_dict() or {}
    current_status = workload_data.get("status", "ACTIVE")

    if current_status != "DECOMMISSIONED":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot archive workload '{clean_pid}'. Only DECOMMISSIONED workloads can be archived (current status: '{current_status}').",
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        doc_ref.set({
            "status": "ARCHIVED",
            "archived_at": now_iso,
            "archived_by": admin_email,
        }, merge=True)

        audit_ref = doc_ref.collection("audit_logs").document()
        audit_ref.set({
            "action": "WORKLOAD_ARCHIVED",
            "operator_email": admin_email,
            "timestamp": now_iso,
        })
        logger.info(f"Workload '{clean_pid}' archived by {admin_email}")
    except Exception as e:
        logger.error(f"Failed to archive workload '{clean_pid}': {e}")
        raise HTTPException(status_code=500, detail=f"Failed to archive workload: {e}")

    return ArchiveWorkloadResponse(
        status="ARCHIVED",
        product_id=clean_pid,
        archived_at=now_iso,
        archived_by=admin_email,
        message=f"Workload '{clean_pid}' has been moved to archive.",
    )


@router.post("/api/workloads/{product_id}/unarchive", response_model=UnarchiveWorkloadResponse, dependencies=[require(ADMIN)])
def unarchive_workload_endpoint(product_id: str, request: Request):
    verify_admin_access(request)
    """
    Restores an archived workload back to DECOMMISSIONED status:
    1. Validates admin authentication.
    2. Guard: Only workloads currently in ARCHIVED status can be restored.
    3. Updates Firestore status to 'DECOMMISSIONED' and clears archived_at and archived_by.
    4. Writes an audit record to the workload's audit trail.
    """
    admin_email = getattr(request.state, "user_email", "admin-console")
    clean_pid = product_id.strip().lower()

    if not db:
        raise HTTPException(status_code=500, detail="Database client is unavailable.")

    doc_ref = db.collection("workloads").document(clean_pid)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Workload '{clean_pid}' not found.")

    workload_data = doc.to_dict() or {}
    current_status = workload_data.get("status", "ACTIVE")

    if current_status != "ARCHIVED":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot unarchive workload '{clean_pid}'. Only ARCHIVED workloads can be unarchived (current status: '{current_status}').",
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        doc_ref.set({
            "status": "DECOMMISSIONED",
            "archived_at": None,
            "archived_by": None,
        }, merge=True)

        audit_ref = doc_ref.collection("audit_logs").document()
        audit_ref.set({
            "action": "WORKLOAD_UNARCHIVED",
            "operator_email": admin_email,
            "timestamp": now_iso,
        })
        logger.info(f"Workload '{clean_pid}' unarchived by {admin_email}")
    except Exception as e:
        logger.error(f"Failed to unarchive workload '{clean_pid}': {e}")
        raise HTTPException(status_code=500, detail=f"Failed to unarchive workload: {e}")

    return UnarchiveWorkloadResponse(
        status="DECOMMISSIONED",
        product_id=clean_pid,
        unarchived_at=now_iso,
        unarchived_by=admin_email,
        message=f"Workload '{clean_pid}' has been restored to decommissioned status.",
    )


@router.post("/api/workloads/{product_id}/deploy-to-folder", response_model=WorkloadSummary, dependencies=[require(ADMIN)])
def deploy_workload_to_folder_endpoint(
    product_id: str,
    req: DeployToFolderRequest,
    request: Request,
    response: Response = None,
):
    """
    Branch-Backed Promotion ("Deploy to New Folder"):
    1. Validates operator access via verify_workload_access(require_manager=True)
    2. Verifies source workload exists and is ACTIVE
    3. Normalizes and validates new_product_id (must not already exist)
    4. Creates the new branch in the shared GitHub repository from current main HEAD
    5. Vends new isolated GCP project in the destination folder
    6. Registers new workload in Firestore tracking the shared repo and new branch
    7. Dispatches spec-intake-events to trigger build and deployment
    """
    # FD-4N / FD25-16 (owner Q2): ADMIN only (route policy + this check), and the destination must be the managed
    # workloads root or a folder below it (CRM v3 parent walk, fail closed). Validated BEFORE any side effect.
    verify_admin_access(request)
    _refuse_new_run_in_maintenance("deploy to a new folder")  # settings-toggles
    admin_email = getattr(request.state, "user_email", "operator")
    source_pid = product_id.strip().lower()
    clean_new_pid = re.sub(r"[^a-z0-9\-]", "-", req.new_product_id.strip().lower()).strip("-")
    if not clean_new_pid or len(clean_new_pid) < 3:
        raise HTTPException(status_code=400, detail="Invalid new_product_id: must be at least 3 characters alphanumeric/hyphens.")
    # RT14 RT F1: the same id rule as the create form (RT14-37 / RT14-02), before any side effect; the gateway refuses
    # these ids before it has a store client, so a promotion that passed here would stay PROVISIONING with no run.
    try:
        validate_product_id(clean_new_pid)
    except UnsafePathError:
        raise HTTPException(status_code=400, detail="Invalid new_product_id: at most 63 lowercase letters, digits and "
                                                    "hyphens, starting and ending with a letter or digit.") from None
    if clean_new_pid in PLATFORM_PSEUDO_WORKLOADS:
        raise HTTPException(status_code=400,
                            detail=f"Invalid new_product_id: '{clean_new_pid}' is reserved for the platform.")
    try:
        managed_root = managed_root_folder()
    except FolderConfigError as cfg_err:
        raise HTTPException(status_code=503, detail=str(cfg_err))
    dest_folder = normalize_folder_name(req.destination_folder_id)
    if not dest_folder or not is_descendant_of_root(dest_folder):
        raise HTTPException(
            status_code=400,
            detail=f"destination_folder_id must be {managed_root} or one of its sub-folders (organizations/* is refused).",
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    source_data = {}
    if db:
        try:
            source_doc = db.collection("workloads").document(source_pid).get()
            if not source_doc.exists:
                raise HTTPException(status_code=404, detail=f"Source workload '{source_pid}' not found.")
            source_data = source_doc.to_dict() or {}
            if source_data.get("status") in ["QUARANTINED", "BILLING_UNLINKED"]:
                raise HTTPException(
                    status_code=423,
                    detail=f"Source workload '{source_pid}' is locked in {source_data.get('status')} due to a budget breach. Resolve pending HITL budget remediation before deploying to a folder.",
                )

            target_check = db.collection("workloads").document(clean_new_pid).get()
            if target_check.exists:
                raise HTTPException(status_code=409, detail=f"Workload '{clean_new_pid}' already exists.")
        except Exception as e:
            if hasattr(e, "status_code"):
                raise
            logger.warning(f"Error checking workloads in Firestore: {e}")

    source_status = source_data.get("status")
    if source_status and source_status in ("DECOMMISSIONED", "DELETED"):
        raise HTTPException(status_code=400, detail=f"Cannot promote decommissioned workload '{source_pid}'.")

    # FD-4N (red-team H1): the repository comes only from the source workload doc; never a guessed default.
    github_repo = source_data.get("github_repo")
    if not github_repo:
        raise HTTPException(status_code=409, detail=f"Source workload '{source_pid}' has no registered github_repo.")

    target_branch = req.target_branch.strip() or "prod"
    source_branch = source_data.get("default_branch", "main")

    # 1. Create Git branch in repository
    if github_repo:
        try:
            main_mod = get_caller_main_module()
            active_branch_fn = getattr(main_mod, "create_or_verify_branch", create_or_verify_branch)
            active_branch_fn(
                repo_full_name=github_repo,
                branch_name=target_branch,
                source_branch=source_branch,
            )
            logger.info(f"Created branch '{target_branch}' in repo '{github_repo}' for workload '{clean_new_pid}'")
        except Exception as gh_err:
            # FD25-16: no silent PROVISIONING-forever; fail before registering anything.
            logger.error(f"Git branch creation failed for '{clean_new_pid}': {gh_err}")
            raise HTTPException(status_code=502, detail=f"Could not create branch '{target_branch}' in '{github_repo}': {gh_err}")

    # 2. Destination folder was validated above (dest_folder)
    folder_name = None
    if db:
        try:
            f_key = dest_folder.replace("folders/", "folders_")
            f_doc = db.collection("managed_folders").document(f_key).get()
            if f_doc.exists:
                folder_name = f_doc.to_dict().get("display_name")
        except Exception:
            pass

    clean_base = re.sub(r"[^a-z0-9]", "-", clean_new_pid.lower()).strip("-")
    if 6 <= len(clean_base) <= 30 and clean_base[0].isalpha():
        target_project_id = clean_base
    else:
        clean_prefix = clean_base[:23].rstrip("-") if len(clean_base) > 23 else clean_base
        if not clean_prefix or not clean_prefix[0].isalpha():
            clean_prefix = f"p-{clean_prefix}".rstrip("-")[:23]
        target_project_id = f"{clean_prefix}-{uuid.uuid4().hex[:6]}".strip("-")[:30].rstrip("-")
    budget = float(source_data.get("budget_ceiling_monthly_usd", 50.0))
    promoted_iac_engine = source_data.get("iac_engine", "TERRAFORM")
    promoted_code_freeze = _freeze_new_workloads(get_platform_settings)

    new_workload_record = {
        "product_id": clean_new_pid,
        "project_id": target_project_id,
        "github_repo": github_repo,
        "default_branch": target_branch,
        "folder_id": dest_folder,
        "folder_name": folder_name or dest_folder,
        "status": "PROVISIONING",
        "budget_ceiling_monthly_usd": budget,
        "current_spend_usd": 0.0,
        "projected_monthly_spend_usd": 0.0,
        "spend_last_updated_at": now_iso,
        "is_overrun_projected": False,
        "service_url": "",
        "created_at": now_iso,
        "description": f"Promoted from {source_pid} to {dest_folder} (branch: {target_branch})",
        "initialized_by": admin_email,
        "promoted_from_product_id": source_pid,
        "promoted_at": now_iso,
        "is_castor": False,
        # FD-4CU (owner 10-21): the promoted workload is new (create() below): Code Freeze on while
        # governance.freeze_new_workloads is on (default; unreadable settings -> frozen). Never copied from the source.
        "code_freeze": promoted_code_freeze,
        "sre_auto_healing_enabled": True,
        "refactor_scanner_enabled": True,
        "require_human_code_review": True,
        "iac_engine": promoted_iac_engine,
    }
    # OSS-D23 / RT F1: the promoted workload is a NEW Agent-mode workload: it gets the private platform default listing
    # the promoting administrator's verified identity, never public by omission and never a copy of the source record.
    new_workload_record.update(_default_access_fields(request))

    promotion_request_id: Optional[str] = None   # set once its feature request is saved: no store, no id on the event
    if db:
        from google.api_core import exceptions as _gexc

        try:
            try:
                # RT F5 (same rule): create() semantics, so an existing document is never overwritten.
                db.collection("workloads").document(clean_new_pid).create(new_workload_record)
            except _gexc.AlreadyExists:
                raise HTTPException(status_code=409, detail=f"Workload '{clean_new_pid}' already exists.")
            logger.info(f"Registered promoted workload '{clean_new_pid}' in Firestore by {admin_email}")

            req_id = f"spec-{clean_new_pid}-{int(time.time())}"
            spec_doc = {
                "request_id": req_id,
                "product_id": clean_new_pid,
                "project_id": target_project_id,
                "github_repo": github_repo,
                "title": f"Promotion Build: {clean_new_pid} ({target_branch})",
                "description": f"Deploy environment promoted from {source_pid} under folder {dest_folder}.",
                "change_type": "PROMOTION",
                "priority": "HIGH",
                "target_components": "All Services & Infrastructure",
                "acceptance_criteria": f"Build and deploy branch '{target_branch}' into fresh child project in '{dest_folder}'.",
                "status": "IN_PROGRESS",
                "created_at": now_iso,
                "created_by": admin_email,
            }
            db.collection("feature_requests").document(req_id).set(spec_doc)
            promotion_request_id = req_id
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to persist promoted workload '{clean_new_pid}' to Firestore: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to save workload to Firestore: {e}")

    # Dispatch to Pub/Sub. FD25-16 / RT14-19: the same typed first-build dispatch as the create form (no publisher
    # 503, publish error 502, timeout 504 OUTCOME_UNKNOWN: the event may still arrive, so it is not marked FAILED).
    # The publisher is looked up like the branch creation above and the retrigger (the main module's getter).
    pub_client = getattr(get_caller_main_module(), "get_pubsub_publisher", get_pubsub_publisher)()
    current_proj = project_id or os.getenv("PROJECT_ID", "")
    intake_payload = {
        "trace_id": f"intake-{clean_new_pid}-{uuid.uuid4().hex[:6]}",
        "product_id": clean_new_pid,
        "project_id": target_project_id,
        "github_repo": github_repo,
        "default_branch": target_branch,
        "folder_id": dest_folder,
        "title": f"Promotion Build: {clean_new_pid} ({target_branch})",
        "spec_text": f"Deploy environment promoted from {source_pid} under folder {dest_folder}.",
        "source_channel": "deploy_to_folder",
        "created_at": now_iso,
        "budget_ceiling_monthly_usd": budget,
        "iac_engine": promoted_iac_engine,
    }
    # RESUME-DEVELOPER-TASK-DAG: same as the create form; the gateway records it on the run.
    if promotion_request_id:
        intake_payload["request_id"] = promotion_request_id
    # BUILD-ADMISSION-QUEUE (G4): the promotion build takes a slot first (as the create form).
    promotion_queue_view = _dispatch_first_build(
        product_id=clean_new_pid, pub_client=pub_client, current_project=current_proj, intake_payload=intake_payload,
        source="deploy_to_folder", title=intake_payload["title"], request_id=promotion_request_id, now_iso=now_iso,
        response=response)

    return WorkloadSummary(
        product_id=clean_new_pid,
        project_id=target_project_id,
        github_repo=github_repo,
        default_branch=target_branch,
        folder_id=dest_folder,
        folder_name=folder_name,
        status="PROVISIONING",
        budget_ceiling_monthly_usd=budget,
        current_spend_usd=0.0,
        projected_monthly_spend_usd=0.0,
        spend_last_updated_at=now_iso,
        is_overrun_projected=False,
        service_url="",
        created_at=now_iso,
        is_castor=False,
        code_freeze=promoted_code_freeze,
        iac_engine=promoted_iac_engine,
        build_queue=promotion_queue_view,
    )


# ------------------------------------------------------------------------------
# IaC Module & Bundle Upgrade Engine APIs
# ------------------------------------------------------------------------------

@router.get("/api/workloads/{product_id}/iac-drift-status", response_model=IaCDriftStatusResponse, dependencies=[require(WORKLOAD())])
def get_workload_iac_drift_status(product_id: str, request: Request):
    """
    Analyzes the workload repository's vendored Golden Modules and Composite Bundles
    using cryptographic SHA-256 content hashing and version manifests.
    Computes exact drift with Zero-LLM calls.
    """
    verify_workload_access(product_id, request)
    firestore_client = get_db()
    if not firestore_client:
        raise HTTPException(status_code=503, detail="Firestore client unavailable.")

    w_doc = firestore_client.collection("workloads").document(product_id).get()
    if not w_doc.exists:
        raise HTTPException(status_code=404, detail=f"Workload '{product_id}' not found.")
    w_data = w_doc.to_dict() or {}

    repo_id = w_data.get("github_repo")
    if not repo_id:
        return IaCDriftStatusResponse(
            workload_id=product_id,
            drift_detected=False,
            modules=[],
            total_modules=0,
            outdated_modules=0,
            last_upgrade_at=w_data.get("last_iac_upgrade_at"),
            last_upgrade_by=w_data.get("last_iac_upgrade_by"),
            last_upgrade_status=w_data.get("last_iac_upgrade_status"),
        )

    # Fetch file tree from VCS provider
    from shared.vcs_provider import VCSProviderFactory
    vcs_type = w_data.get("vcs_provider", "GITHUB")
    def_branch = w_data.get("default_branch", "main")

    try:
        provider = VCSProviderFactory.get_provider(vcs_type, product_id=product_id)
        # FD-4DC: the whole tree or a typed refusal (the deploy's limit, 2500 files; was a silent 300-file cut)
        files = provider.fetch_file_tree(repo_id, branch=def_branch, require_complete=True)
    except IncompleteRepoTreeError as e:
        logger.warning(f"Drift of '{repo_id}' not inspected: {e}")
        raise _repo_tree_incomplete(e, "Drift was not inspected and the cached drift summary was not changed.")
    except Exception as e:
        logger.warning(f"Failed to fetch files from repository '{repo_id}' for drift inspection: {e}")
        return IaCDriftStatusResponse(
            workload_id=product_id,
            drift_detected=bool(w_data.get("iac_drift_detected", False)),
            modules=[],
            total_modules=0,
            outdated_modules=int(w_data.get("iac_drift_count", 0)),
            last_upgrade_at=w_data.get("last_iac_upgrade_at"),
            last_upgrade_by=w_data.get("last_iac_upgrade_by"),
            last_upgrade_status=w_data.get("last_iac_upgrade_status"),
        )

    try:
        resp = inspect_workload_iac_drift(files, workload_id=product_id, firestore_client=firestore_client)
    except IncompleteRepoTreeError as e:   # FD-4DC: a remote custom module's upstream repository, read partially
        logger.warning(f"Drift of '{repo_id}' not inspected: {e}")
        raise _repo_tree_incomplete(e, "Drift was not inspected and the cached drift summary was not changed.")
    resp.last_upgrade_at = w_data.get("last_iac_upgrade_at")
    resp.last_upgrade_by = w_data.get("last_iac_upgrade_by")
    resp.last_upgrade_status = w_data.get("last_iac_upgrade_status")

    # Update parent doc with cached drift summary for fast catalog loading
    try:
        firestore_client.collection("workloads").document(product_id).update({
            "iac_drift_detected": resp.drift_detected,
            "iac_drift_count": resp.outdated_modules,
        })
    except Exception:
        pass

    return resp


@router.get("/api/workloads/{product_id}/iac-upgrades", response_model=IaCUpgradeHistoryResponse, dependencies=[require(WORKLOAD())])
def get_workload_iac_upgrades(product_id: str, request: Request):
    """
    Returns the immutable audit history of all IaC module and bundle upgrades for this workload.
    """
    verify_workload_access(product_id, request)
    firestore_client = get_db()
    upgrades = get_iac_upgrade_history(product_id, limit=50, firestore_client=firestore_client)
    return IaCUpgradeHistoryResponse(workload_id=product_id, upgrades=upgrades)


def _record_iac_upgrade_ledger(firestore_client, product_id: str, upgrade_id: str, vcs_type, repo_identifier: str,
                               branch: str, base_branch, commit_sha, pr_info) -> Dict[str, Any]:
    """FD-4P: record the IaC-upgrade branch/PR in the PR ledger (origin IAC_UPGRADE_CC) so any later StackVend
    merge or close is bound to exactly what was created here. Best-effort: the PR stays for human review either way;
    the outcome is returned for the upgrade record (RT F8: say so when it was not recorded)."""
    try:
        from shared import vcs_ledger

        kind = str(vcs_type or "GITHUB").strip().upper()
        if kind not in vcs_ledger.PROVIDERS:
            logger.warning(f"IaC upgrade {upgrade_id}: unsupported vcs_provider {vcs_type!r}; no PR ledger entry")
            return {"ledger_recorded": False, "ledger_reason": f"unsupported vcs_provider {vcs_type!r}"}
        repo_full = resolve_repo_identity(repo_identifier)[2] if resolve_repo_identity else repo_identifier
        pr = pr_info if (kind == "GITHUB" and isinstance(pr_info, dict)) else None
        problems = vcs_ledger.creation_problems(kind, repo_full_name=repo_full, branch=branch, base_branch=base_branch,
                                                commit_sha=commit_sha, pull_request=pr)
        if problems:
            logger.error(f"IaC upgrade {upgrade_id}: no PR ledger entry: {problems}",
                         extra={"security_event": "pr_identity_mismatch"})
            return {"ledger_recorded": False, "ledger_reason": "; ".join(problems)}
        vcs_ledger.record_created(
            firestore_client, provider=kind, repo_full_name=repo_full, repo_id=pr.get("base_repo_id") if pr else None,
            product_id=product_id, trace_id=upgrade_id, origin=vcs_ledger.ORIGIN_IAC_UPGRADE_CC, branch=branch,
            base_branch=base_branch, head_sha=commit_sha, pr_number=pr.get("pr_number") if pr else None,
            pr_url=pr.get("pull_request_url") if pr else None)
        return {"ledger_recorded": True, "ledger_reason": None}
    except Exception as e:  # noqa: BLE001
        logger.error(f"IaC upgrade {upgrade_id}: PR ledger entry not recorded: {e}")
        return {"ledger_recorded": False, "ledger_reason": f"{type(e).__name__}: {e}"}


class UpgradePreflightParseError(ValueError):
    """An upgraded IaC file does not parse. `path` names it; nothing is committed (upgrade ROLLED_BACK)."""

    error_class = "IAC_PREFLIGHT_PARSE_ERROR"

    def __init__(self, path: str, reason: str):
        super().__init__(f"Syntax error in {path}: {reason}")
        self.path, self.reason = path, reason


class UpgradePreflightParserRefused(ValueError):
    """FD-4DC RT F1: python-hcl2 refused an upgraded .tf file and no OpenTofu/Terraform parser was available to give
    a real verdict. The file is NOT proven broken (python-hcl2 7.3.1 refuses some valid HCL), so this is never
    reported as a syntax error. Nothing is committed (upgrade ROLLED_BACK)."""

    error_class = "IAC_PREFLIGHT_PARSER_REFUSED"

    def __init__(self, path: str, reason: str):
        super().__init__(
            f"{self.error_class}: python-hcl2 7.3.1 could not parse {path} ({reason}) and no OpenTofu parser is "
            f"available in this service to decide. The file is not proven broken: python-hcl2 does not accept some "
            f"valid HCL, for example a continuation line that starts with an operator inside parentheses. The "
            f"platform did not change the file. Nothing was committed")
        self.path, self.reason = path, reason


class UpgradePreflightUnavailable(RuntimeError):
    """python-hcl2 is not importable: the pre-flight cannot run (a deployment defect). Nothing is committed."""

    error_class = "IAC_PREFLIGHT_UNAVAILABLE"


def _opentofu_parse_verdict(text: str, path: str) -> Optional[List[str]]:
    """OpenTofu/Terraform's own parser (`fmt` on stdin, shared/hcl_utils.py; syntax only, read-only): [] = parses,
    [message] = refused, None = no binary here or it could not decide. The CC image ships no binary today, so in
    production this is None; the terraform MCP server has no parse endpoint (its /validate is a full init + validate
    of a workload root, not a per-file syntax verdict), so it is not consulted."""
    from shared import hcl_utils

    binary = hcl_utils.find_hcl_parser_binary()
    if not binary:
        return None
    return hcl_utils.hcl_parse_errors(text, filename=path, parser_bin=binary)


def _preflight_parse_upgraded_iac(files: Dict[str, str]) -> None:
    """Upgrade IaC pre-flight: every `.tf.json` file parses with json and every `.tf` file parses with python-hcl2 (the
    pinned parser, requirements.txt). The input is read, never changed. A leading UTF-8 byte-order mark and CRLF line
    endings are normalized first (HCL allows both, python-hcl2 rejects them), as shared/module_inspector.py does.

    FD-4DC RT F1: python-hcl2 7.3.1 refuses some valid HCL, so its refusal alone is never a verdict. Then OpenTofu's
    parser decides when a binary exists: it accepts -> the file passes; it refuses -> UpgradePreflightParseError
    ("Syntax error", OpenTofu's message). No binary -> UpgradePreflightParserRefused (IAC_PREFLIGHT_PARSER_REFUSED),
    which never says "syntax error"."""
    for path in sorted(files):
        if path.endswith(".tf.json"):
            try:
                json.loads(files[path])
            except ValueError as e:
                raise UpgradePreflightParseError(path, f"JSON: {e}") from e
    tf_paths = [p for p in sorted(files) if p.endswith(".tf")]
    if not tf_paths:
        return
    try:
        from hcl2.parser import parser as hcl_parser  # python-hcl2==7.3.1 (apps/control-center/requirements.txt)
    except ImportError as e:  # pragma: no cover - environment
        raise UpgradePreflightUnavailable("python-hcl2 is not installed") from e
    hcl = hcl_parser()
    for path in tf_paths:
        text = files[path]
        text = (text[1:] if text.startswith("\ufeff") else text).replace("\r\n", "\n")
        try:
            hcl.parse(text + "\n")
            continue
        except Exception as e:  # noqa: BLE001 - lark raises several exception types for syntax errors
            first_line = (str(e).strip().splitlines() or [""])[0]   # lark appends a long "Expected one of" list
            hcl2_reason, hcl2_err = f"{type(e).__name__}: {first_line}", e
        verdict = _opentofu_parse_verdict(text, path)
        if verdict == []:
            continue                                   # OpenTofu parses it: python-hcl2's gap, not a broken file
        if verdict:
            raise UpgradePreflightParseError(path, verdict[0]) from hcl2_err
        raise UpgradePreflightParserRefused(path, hcl2_reason) from hcl2_err


IDENTITY_UNVERIFIED = "IDENTITY_UNVERIFIED"


def _verified_caller_email(request: Request, stage: str) -> str:
    """RT14-34: the e-mail the auth middleware verified (request.state.user_email). Never a request-body value or a
    placeholder: without a verified identity the action is refused (401 IDENTITY_UNVERIFIED, typed)."""
    email = getattr(getattr(request, "state", None), "user_email", None)
    if not isinstance(email, str) or not email.strip():
        raise HTTPException(status_code=401, detail={
            "error_class": IDENTITY_UNVERIFIED, "stage": stage,
            "detail": "No verified caller identity on this request; nothing was changed."})
    return email.strip()


@router.post("/api/workloads/{product_id}/upgrade-iac", dependencies=[require(WORKLOAD(manager=True))])
def trigger_workload_iac_upgrade(product_id: str, req: TriggerIaCUpgradeRequest, request: Request):
    """
    Executes a pure deterministic, Zero-LLM IaC upgrade of vendored modules and bundles.
    Performs pre-flight compiler validation, opens a pull request, and records immutable audit log.
    """
    verify_workload_access(product_id, request, require_manager=True)
    firestore_client = get_db()
    if not firestore_client:
        raise HTTPException(status_code=503, detail="Firestore client unavailable.")

    w_doc = firestore_client.collection("workloads").document(product_id).get()
    if not w_doc.exists:
        raise HTTPException(status_code=404, detail=f"Workload '{product_id}' not found.")
    w_data = w_doc.to_dict() or {}

    if w_data.get("code_freeze"):
        raise HTTPException(status_code=423, detail=f"Workload '{product_id}' has Code Freeze enabled. Modifications prohibited.")

    if w_data.get("status") in ["QUARANTINED", "BILLING_UNLINKED"]:
        raise HTTPException(
            status_code=423,
            detail=f"Workload '{product_id}' is locked in {w_data.get('status')} due to a budget breach. Resolve pending HITL budget remediation before modifying.",
        )

    repo_id = w_data.get("github_repo")
    if not repo_id:
        raise HTTPException(status_code=400, detail=f"Workload '{product_id}' has no associated code repository.")

    # RT14-34: the audit author is the verified caller (the immutable triggered_by, the commit author name and the PR
    # body all show it); a client-supplied `author` is never an identity, only logged when it differs.
    author_email = _verified_caller_email(request, stage="iac_upgrade")
    if req.author and req.author not in (author_email, "Operator"):
        logger.warning(f"Upgrade IaC for '{product_id}': request body author {req.author[:120]!r} ignored; "
                       f"recorded the verified caller {author_email}")

    # Record start in audit subcollection
    modules_hint = req.modules_to_upgrade or ["all-drifted"]
    upgrade_id = record_iac_upgrade_start(product_id, author_email, modules_hint, firestore_client=firestore_client)

    from shared.vcs_provider import VCSProviderFactory
    vcs_type = w_data.get("vcs_provider", "GITHUB")
    def_branch = w_data.get("default_branch", "main")

    not_done = "Nothing was committed and no pull request was opened."
    try:
        provider = VCSProviderFactory.get_provider(vcs_type, product_id=product_id)
        # FD-4DC: the whole tree or a typed refusal (the deploy's limit, 2500 files; was a silent 300-file cut)
        existing_files = provider.fetch_file_tree(repo_id, branch=def_branch, require_complete=True)
    except IncompleteRepoTreeError as e:
        refusal = _repo_tree_incomplete(e, not_done)
        record_iac_upgrade_complete(
            product_id, upgrade_id, status="FAILED", validation_error=refusal.detail,
            author=author_email, firestore_client=firestore_client
        )
        raise refusal
    except Exception as e:
        record_iac_upgrade_complete(
            product_id, upgrade_id, status="FAILED",
            validation_error=f"VCS fetch failed: {str(e)}",
            author=author_email, firestore_client=firestore_client
        )
        raise HTTPException(status_code=500, detail=f"Failed to fetch repository files: {e}")

    # Re-vendor files deterministically
    try:
        updated_files, upgraded_mods, details = upgrade_workload_iac_vendoring(
            files=existing_files,
            modules_to_upgrade=req.modules_to_upgrade,
            author=author_email,
            firestore_client=firestore_client,
        )
    except IncompleteRepoTreeError as e:   # FD-4DC: a remote custom module's upstream repository, read partially
        refusal = _repo_tree_incomplete(e, not_done)
        record_iac_upgrade_complete(
            product_id, upgrade_id, status="FAILED", validation_error=refusal.detail,
            author=author_email, firestore_client=firestore_client
        )
        raise refusal
    except Exception as e:
        record_iac_upgrade_complete(
            product_id, upgrade_id, status="FAILED",
            validation_error=f"Re-vendoring engine failed: {str(e)}",
            author=author_email, firestore_client=firestore_client
        )
        raise HTTPException(status_code=500, detail=f"IaC re-vendoring failed: {e}")

    if not upgraded_mods:
        record_iac_upgrade_complete(
            product_id, upgrade_id, status="SUCCESS",
            details={"message": "All vendored modules are already up to date."},
            drift_detected=False, drift_count=0,
            author=author_email, firestore_client=firestore_client
        )
        return {
            "status": "SUCCESS",
            "upgrade_id": upgrade_id,
            "message": "All vendored modules are already up to date.",
            "upgraded_modules": [],
        }

    # Identify which files actually changed
    files_to_commit: Dict[str, str] = {}
    for p, c in updated_files.items():
        if existing_files.get(p) != c:
            files_to_commit[p] = c

    # FD-4DC-e: the vendored .tf files the new module version dropped (upgraded modules only; anything else the
    # engine removed is a defect and nothing is committed).
    try:
        files_to_delete = module_files_removed_by_upgrade(existing_files, updated_files, upgraded_mods)
    except ModuleDeletionScopeError as e:
        detail = f"{e.error_class}: {e}. {not_done}"
        record_iac_upgrade_complete(
            product_id, upgrade_id, status="FAILED", validation_error=detail,
            author=author_email, firestore_client=firestore_client
        )
        raise HTTPException(status_code=500, detail=detail)

    # Pre-flight validation gate: every upgraded .tf / .tf.json file must parse (python-hcl2 / json; was a `{` / `}`
    # count, which refused a lone brace in a string and passed a balanced but broken file).
    validation_err = None
    try:
        _preflight_parse_upgraded_iac(files_to_commit)
    except (UpgradePreflightParseError, UpgradePreflightParserRefused) as e:   # 400, ROLLED_BACK (both)
        validation_err = str(e)
    except UpgradePreflightUnavailable as e:
        detail = f"{e.error_class}: {e}. {not_done}"
        record_iac_upgrade_complete(
            product_id, upgrade_id, status="FAILED", validation_error=detail,
            author=author_email, firestore_client=firestore_client
        )
        raise HTTPException(status_code=503, detail=detail)

    if validation_err:
        record_iac_upgrade_complete(
            product_id, upgrade_id, status="ROLLED_BACK",
            validation_error=validation_err,
            author=author_email, firestore_client=firestore_client
        )
        raise HTTPException(status_code=400, detail=f"Pre-flight IaC validation failed: {validation_err}. Rollback executed.")

    # Create upgrade branch and commit files
    branch_name = f"iac-upgrade/{product_id}-{uuid.uuid4().hex[:6]}"
    commit_msg = f"chore(iac): upgrade vendored modules ({', '.join(upgraded_mods)}) to latest"
    pr_title = f"🔄 Upgrade IaC Modules to Latest [{product_id}]"
    pr_body = (
        f"### Deterministic IaC Module & Bundle Upgrade\n\n"
        f"**Triggered By:** `{author_email}`\n"
        f"**Upgraded Modules:** {', '.join([f'`{m}`' for m in upgraded_mods])}\n"
        f"**Audit Upgrade ID:** `{upgrade_id}`\n\n"
        f"This pull request was deterministically vendored with zero LLM alterations. "
        f"Core infrastructure root configs (`infra/main.tf`), human overrides (`infra/human*.tf`), "
        f"and application services (`apps/*`) were strictly preserved.\n"
    )

    try:
        # Create branch from main
        provider.create_or_verify_branch(repo_id, branch_name=branch_name, source_branch=def_branch)
        commit_sha = provider.commit_files(
            repo_id,
            branch=branch_name,
            files=files_to_commit,
            commit_message=commit_msg,
            author_name=f"{author_email} (via StackVend IaC Engine)",
            author_email=(os.getenv("STACKVEND_GIT_AUTHOR_EMAIL") or "stackvend-agent@noreply.invalid").strip(),  # UPGRADE-IAC-AUTHOR (owner 10-27): same author as every platform commit
            **({"files_to_delete": files_to_delete} if files_to_delete else {}),   # FD-4DC-e
        )

        # Open Pull Request
        pr_info = provider.create_pull_request(
            repo_id,
            title=pr_title,
            body=pr_body,
            head_branch=branch_name,
            base_branch=def_branch,
        )
        # FD-4P: the provider returns `pr_number` / `pull_request_url` (the old `number` / `html_url` keys were
        # always None). The PR is left for human review: there is no QA evidence for an IaC upgrade, so the old
        # auto-merge (dormant behind that key bug) is removed (lane 16 Q8: IaC-upgrade PRs never auto-merge).
        pr_num = pr_info.get("pr_number") if isinstance(pr_info, dict) else None
        pr_url = pr_info.get("pull_request_url") if isinstance(pr_info, dict) else None
        ledger_outcome = _record_iac_upgrade_ledger(firestore_client, product_id, upgrade_id, vcs_type, repo_id,
                                                    branch_name, def_branch, commit_sha, pr_info)

        record_iac_upgrade_complete(
            product_id,
            upgrade_id,
            status="SUCCESS",
            commit_sha=commit_sha,
            pr_number=pr_num,
            pr_url=pr_url,
            details={"upgraded_modules": upgraded_mods, "files_updated": list(files_to_commit.keys()),
                     **({"files_deleted": files_to_delete} if files_to_delete else {}), **ledger_outcome},
            drift_detected=False,
            drift_count=0,
            author=author_email,
            firestore_client=firestore_client,
        )

        return {
            "status": "SUCCESS",
            "upgrade_id": upgrade_id,
            "workload_id": product_id,
            "upgraded_modules": upgraded_mods,
            "commit_sha": commit_sha,
            "branch_name": branch_name,
            "pull_request_url": pr_url,
            "pull_request_number": pr_num,
            "files_updated_count": len(files_to_commit),
            **({"files_deleted": files_to_delete} if files_to_delete else {}),
        }
    except Exception as e:
        record_iac_upgrade_complete(
            product_id,
            upgrade_id,
            status="FAILED",
            validation_error=str(e),
            author=author_email,
            firestore_client=firestore_client,
        )
        logger.error(f"IaC upgrade commit/PR failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to commit IaC upgrade: {e}")


# ==============================================================================
# Autonomous Sandbox Workload Lifecycle Endpoints
# ==============================================================================

def _sandbox_lifecycle_via_vending(clean_pid: str, body: Dict[str, Any], request: Request):
    """Lane 18 S2: vending's vend-time provenance is the only TTL authority, so extend / promote / confirm go through
    vending POST /projects/{id}/lifecycle (guard checks 1-7 run there first). Returns (outcome, ledger_only):
    ledger_only is True when vending answers exactly LEDGER_UNPROVENANCED (no vend-time record: a workload vended
    before lane 18) or SANDBOX_NOT_ELIGIBLE (provenance says it is not an auto-decommission sandbox). Vending never
    TTL-deletes either kind, so the CC's own countdown for them is display-only and may be updated in the ledger."""
    outcome = destructive_actions.call_vending(
        make_vending_request, f"/projects/{clean_pid}/lifecycle", body, request=request, timeout=30.0)
    ledger_only = (not outcome.ok) and outcome.code in LEDGER_ONLY_LIFECYCLE_CODES
    return outcome, ledger_only


# Vending refusals after which an extend/promote may still update the CC's display countdown (see above). Exact codes.
LEDGER_ONLY_LIFECYCLE_CODES = frozenset({"LEDGER_UNPROVENANCED", "SANDBOX_NOT_ELIGIBLE"})


@router.post("/api/workloads/{product_id}/sandbox/extend", response_model=ExtendSandboxResponse, dependencies=[require(ADMIN)])
def extend_sandbox_endpoint(
    product_id: str,
    request: Request,
    payload: Optional[ExtendSandboxRequest] = None,
):
    """
    Extends an active sandbox workload lifespan by 1-30 days (default: 30).
    Enforces a strict cumulative maximum ceiling of 90 days and at most 3 extensions.
    Lane 18 S2: the extension is applied by project-vending to the vend-time expiry it enforces (EXTEND); the ledger
    countdown mirrors it. A non-200 from vending -> HTTP 502 with vending's {code, detail}, ledger unchanged (except the
    display-only case documented in _sandbox_lifecycle_via_vending).
    """
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin-console")
    clean_pid = product_id.strip().lower()
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    additional_days = payload.extend_days if payload and payload.extend_days is not None else 30
    reason = (payload.reason if payload else "") or "Operator manual sandbox extension"

    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")

    doc_ref = db.collection("workloads").document(clean_pid)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Workload '{clean_pid}' not found.")
    data = doc.to_dict() or {}

    if not data.get("is_sandbox"):
        raise HTTPException(status_code=400, detail=f"Workload '{clean_pid}' is not designated as a sandbox environment.")

    if data.get("status") == "DECOMMISSIONED":
        raise HTTPException(status_code=400, detail=f"Cannot extend decommissioned workload '{clean_pid}'.")

    current_ext_count = int(data.get("extension_count", 0))
    current_cum_days = int(data.get("cumulative_lifespan_days", data.get("sandbox_ttl_days", 30)))
    previous_expires_at = data.get("sandbox_expires_at") or now_iso

    # Validate extension rules (90d cumulative ceiling / max 3 extensions)
    allowed, err_msg = validate_extension(
        current_cumulative_days=current_cum_days,
        current_extension_count=current_ext_count,
        extension_days=additional_days,
    )
    if not allowed:
        raise HTTPException(status_code=400, detail=err_msg)

    outcome, ledger_only = _sandbox_lifecycle_via_vending(
        clean_pid, {"action": "EXTEND", "ttl_days": additional_days}, request)
    if not outcome.ok and not ledger_only:
        return destructive_actions.failure_response(outcome, action="Sandbox extend", product_id=clean_pid)

    vending_expiry = outcome.body.get("sandbox_expires_at") if outcome.ok else None
    if isinstance(vending_expiry, str) and vending_expiry:
        new_expires_at = vending_expiry
    else:
        try:
            base_dt = datetime.fromisoformat(previous_expires_at.replace("Z", "+00:00"))
        except Exception:
            base_dt = now
        if base_dt < now:
            base_dt = now
        new_expires_at = (base_dt + timedelta(days=additional_days)).isoformat()
    new_ext_count = current_ext_count + 1
    new_cum_days = current_cum_days + additional_days
    days_rem = compute_days_remaining(new_expires_at) or float(additional_days)
    ttl_authority = (destructive_actions.TTL_AUTHORITY_VENDING if outcome.ok
                     else destructive_actions.TTL_AUTHORITY_DISPLAY_ONLY)

    update_fields = {
        "sandbox_expires_at": new_expires_at,
        "sandbox_ttl_days": new_cum_days,
        "cumulative_lifespan_days": new_cum_days,
        "extension_count": new_ext_count,
        "sandbox_decommission_status": "SCHEDULED",
        "warn_t7_sent": False,
        "warn_t2_sent": False,
        "extended_at": now_iso,
        "extended_by": admin_email,
        "ttl_authority": ttl_authority,  # RT H3: on the workload doc, so the card shows a display-only countdown
    }
    doc_ref.set(update_fields, merge=True)

    # Record audit log
    audit_ref = doc_ref.collection("audit_logs").document()
    audit_ref.set({
        "action": "SANDBOX_LIFECYCLE_EXTENDED",
        "operator_email": admin_email,
        "additional_days": additional_days,
        "previous_expires_at": previous_expires_at,
        "new_expires_at": new_expires_at,
        "cumulative_lifespan_days": new_cum_days,
        "extension_count": new_ext_count,
        "reason": reason,
        "ttl_authority": ttl_authority,
        "vending_code": None if outcome.ok else outcome.code,
        "timestamp": now_iso,
    })
    logger.info(f"Extended sandbox '{clean_pid}' by {additional_days} days (Cumulative: {new_cum_days}d, Ext: #{new_ext_count}, {ttl_authority}) by {admin_email}")

    note = "" if outcome.ok else (f" Display only: vending reports {outcome.code}, so this workload is never "
                                  "auto-decommissioned.")
    return ExtendSandboxResponse(
        product_id=clean_pid,
        previous_expires_at=previous_expires_at,
        new_expires_at=new_expires_at,
        sandbox_days_remaining=days_rem,
        cumulative_lifespan_days=new_cum_days,
        extension_count=new_ext_count,
        message=f"Sandbox '{clean_pid}' extended by {additional_days} days. New expiration: {new_expires_at} ({days_rem:.1f} days remaining).{note}",
    )


@router.post("/api/workloads/{product_id}/sandbox/promote", response_model=PromoteSandboxResponse, dependencies=[require(ADMIN)])
def promote_sandbox_endpoint(
    product_id: str,
    request: Request,
):
    """
    Promotes a sandbox workload to a permanent production environment.
    Clears all auto-decommissioning countdowns and timers permanently.
    Lane 18 S2: vending PROMOTE makes the vend-time provenance ineligible first and relabels the project; then the
    ledger is updated. A non-200 from vending -> HTTP 502 with vending's {code, detail}, ledger unchanged.
    """
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin-console")
    clean_pid = product_id.strip().lower()
    now_iso = datetime.now(timezone.utc).isoformat()

    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")

    doc_ref = db.collection("workloads").document(clean_pid)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Workload '{clean_pid}' not found.")
    data = doc.to_dict() or {}

    if not data.get("is_sandbox"):
        raise HTTPException(status_code=400, detail=f"Workload '{clean_pid}' is not designated as a sandbox environment.")

    if data.get("status") == "DECOMMISSIONED":
        raise HTTPException(status_code=400, detail=f"Cannot promote decommissioned workload '{clean_pid}'.")

    outcome, ledger_only = _sandbox_lifecycle_via_vending(clean_pid, {"action": "PROMOTE"}, request)
    if not outcome.ok and not ledger_only:
        return destructive_actions.failure_response(outcome, action="Sandbox promote", product_id=clean_pid)

    update_fields = {
        "is_sandbox": False,
        "sandbox_auto_decommission": False,
        "sandbox_expires_at": None,
        "sandbox_ttl_days": None,
        "sandbox_decommission_status": "PROMOTED",
        "promoted_at": now_iso,
        "promoted_by": admin_email,
        "ttl_authority": (destructive_actions.TTL_AUTHORITY_VENDING if outcome.ok
                          else destructive_actions.TTL_AUTHORITY_DISPLAY_ONLY),
    }
    doc_ref.set(update_fields, merge=True)

    # Record audit log
    audit_ref = doc_ref.collection("audit_logs").document()
    audit_ref.set({
        "action": "SANDBOX_PROMOTED_TO_PRODUCTION",
        "operator_email": admin_email,
        "promoted_at": now_iso,
        "timestamp": now_iso,
        "reason": "Promoted to permanent production workload by operator",
        "ttl_authority": update_fields["ttl_authority"],
        "vending_code": None if outcome.ok else outcome.code,
        "vending_warnings": outcome.body.get("warnings") if outcome.ok else None,
    })
    logger.info(f"Workload '{clean_pid}' promoted to permanent production environment by {admin_email}")

    return PromoteSandboxResponse(
        product_id=clean_pid,
        is_sandbox=False,
        message=f"Workload '{clean_pid}' successfully promoted to permanent production environment. Auto-decommissioning disabled.",
    )


@router.post("/api/workloads/{product_id}/sandbox/confirm", response_model=ConfirmSandboxResponse, dependencies=[require(ADMIN)])
def confirm_sandbox_endpoint(
    product_id: str,
    request: Request,
    payload: Optional[ConfirmSandboxRequest] = None,
):
    """
    Lane 18 S2 (plan §2.4): a human ADMIN confirms that a sandbox whose designation was NOT explicit (keyword-detected)
    may be auto-decommissioned after `ttl_days`. Mints a single-use CONFIRM_SANDBOX approval for this session and calls
    vending /lifecycle CONFIRM_SANDBOX, which relabels the project and records OPERATOR_CONFIRMED in the vend-time
    provenance. A sandbox that is already an explicit auto-decommission sandbox is refused (409: use Extend).
    A non-200 from vending -> HTTP 502 with vending's {code, detail}, ledger unchanged.
    """
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin-console")
    clean_pid = product_id.strip().lower()
    ttl_days = payload.ttl_days if payload and payload.ttl_days is not None else 30

    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")
    doc_ref = db.collection("workloads").document(clean_pid)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Workload '{clean_pid}' not found.")
    data = doc.to_dict() or {}
    if data.get("status") == "DECOMMISSIONED":
        raise HTTPException(status_code=400, detail=f"Cannot confirm decommissioned workload '{clean_pid}'.")
    if data.get("is_castor") is True:
        raise HTTPException(status_code=400, detail="Core platform workload cannot be a sandbox.")
    if data.get("sandbox_auto_decommission") is True \
            and data.get("sandbox_designation_source") in destructive_actions.EXPLICIT_DESIGNATION_SOURCES:
        raise HTTPException(status_code=409, detail=f"Sandbox '{clean_pid}' is already confirmed for auto-decommission; use Extend.")

    target = destructive_actions.resolve_target(clean_pid, data)
    try:
        approval_id = destructive_actions.mint_approval(
            request, action=destructive_actions.CONFIRM_SANDBOX, product_id=clean_pid,
            project_id=target["project_id"], project_number=target["project_number"],
            reason=(payload.reason if payload else None) or "Operator confirmed sandbox auto-decommission")
    except destructive_actions.MintRefused as refused:
        return destructive_actions.refusal_response(refused)

    outcome = destructive_actions.call_vending(
        make_vending_request, f"/projects/{clean_pid}/lifecycle",
        {"action": "CONFIRM_SANDBOX", "ttl_days": ttl_days, "approval_id": approval_id}, request=request, timeout=30.0)
    if not outcome.ok:
        destructive_actions.void_approval(approval_id, outcome)
        return destructive_actions.failure_response(outcome, action="Sandbox confirm", product_id=clean_pid)

    now_iso = datetime.now(timezone.utc).isoformat()
    expires_at = outcome.body.get("sandbox_expires_at") if isinstance(outcome.body.get("sandbox_expires_at"), str) else None
    doc_ref.set({
        "is_sandbox": True,
        "sandbox_auto_decommission": True,
        "sandbox_designation_source": "OPERATOR_CONFIRMED",
        "sandbox_expires_at": expires_at,
        "sandbox_ttl_days": ttl_days,
        "cumulative_lifespan_days": ttl_days,
        "extension_count": 0,
        "sandbox_decommission_status": "SCHEDULED",
        "warn_t7_sent": False,
        "warn_t2_sent": False,
        "sandbox_confirmed_at": now_iso,
        "sandbox_confirmed_by": admin_email,
        "ttl_authority": destructive_actions.TTL_AUTHORITY_VENDING,
    }, merge=True)
    doc_ref.collection("audit_logs").document().set({
        "action": "SANDBOX_AUTO_DECOMMISSION_CONFIRMED",
        "operator_email": admin_email,
        "approval_id": approval_id,
        "ttl_days": ttl_days,
        "sandbox_expires_at": expires_at,
        "timestamp": now_iso,
    })
    logger.info(f"Sandbox '{clean_pid}' confirmed for auto-decommission ({ttl_days} days) by {admin_email}")
    return ConfirmSandboxResponse(
        product_id=clean_pid,
        sandbox_expires_at=expires_at,
        message=f"Sandbox '{clean_pid}' confirmed: it will be auto-decommissioned after {expires_at}.",
    )


@router.post("/api/workloads/sweep-expired-sandboxes", response_model=SandboxSweepResult, dependencies=[require(ADMIN)])
def sweep_expired_sandboxes_endpoint(request: Request):
    """
    Manual sandbox sweep for a human Platform Administrator. C10 (owner 11-07): the daily run is the
    sandbox-workload-sweeper-job Cloud Run job (apps/sandbox-sweeper, Cloud Scheduler castor-sandbox-workload-sweeper);
    nothing machine-calls the Control Center any more, so the route policy is ADMIN (was ADMIN_OR_JOB). Same work:
    shared.sandbox_sweep.run_sweep (T-7 / T-2 notices, deferrals, platform protection, BATCH_LIMIT, vending SANDBOX_TTL
    decommission with the CC's ID token; lane 18 S2: vending decides and executes every delete).
    """
    try:
        result = sandbox_sweep.run_sweep(
            db,
            decommission=lambda pid: destructive_actions.call_vending(
                make_vending_request, f"/projects/{pid}/decommission",
                {"action_class": destructive_actions.SANDBOX_TTL}, request=None,
                timeout=destructive_actions.DECOMMISSION_TIMEOUT_SECONDS),
            cancel_executions=lambda **kw: cancel_workload_active_executions(**kw),
        )
    except sandbox_sweep.SandboxSweepUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return SandboxSweepResult(**result)

