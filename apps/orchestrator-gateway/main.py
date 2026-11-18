"""
Project Castor: Orchestrator Gateway Service
Central API bridge dispatching agent reasoning loops and managing Cloud Workflows state transitions.
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import base64
import hashlib
import json
import logging
import os
import runtime_env  # G1: on_cloud_run() = service or stage-runner job (never K_SERVICE alone)
import re  # FD-4BO: used by PlanApprovalRequest.parse_cost_delta and the release-certificate PR comment
import sys
import time
import traceback
from types import SimpleNamespace
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from developer_agent import DeveloperAgent
# FD-4G: no ImportError fallback -- a missing path guard must crash at boot, never fail open.
from shared.path_safety import GIT_RESERVED, UnsafePathError, validate_manifest_keys, validate_relpath, validate_trace_id
from shared.diagnostics import HTTP_STATUS, RepairBudgetExhausted, StageError

# Ensure the root monorepo is in sys.path so shared packages can be imported.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

# FD-4F (QA-1, QA-3, RL-3): the pipeline gates are hard imports. The old `sys.path` hack into ../qa-runner could
# never import in the gateway image (QASandboxRunner was always None -> QA auto-passed), and a failed import of the
# Stage 2 coordinator or the release gate silently skipped those gates. A missing gate now fails gateway startup;
# Cloud Run keeps the previous revision serving.
from gate_errors import (ErrorClass, GateError, GateFailedError, GateUnavailableError, PlatformDefectError,
                         PrivateIngressUnsupportedError)
# Lane 17 (FD-4AJ / FD-4R / FD-4AG): workflow-level typed errors and the deterministic gate decisions.
from gate_errors import (
    DEPLOY_FAILURE_ROUTE_FIELD,
    DEPLOY_FAILURE_ROUTE_STALE,
    DEPLOY_OWNER_DEVELOPER,
    DEPLOY_OWNER_PLATFORM_DEFECT,
    DEPLOY_OWNERS,
    NO_DEPLOY_FAILURE_ROUTE,
    NON_REMEDIABLE_DEPLOY_CLASSES,
    ContractViolationError,
    MainMovedError,
    OperatorActionRequiredError,
    PolicyRejectedError,
    ReleaseRefusedError,
    SourceCheckUnconfirmedError,
)
# FD-4P / FD-4BB: the PR ledger (what StackVend created) and the exact PR identity every merge is bound to.
from shared import vcs_ledger
from shared.vcs_provider import IncompleteRepoTreeError, PRIdentityMismatch, PRMergeNotCompleted
from shared.providers.serverless_git_provider import ServerlessGitMergeConflict  # FD-4BE: the typed FF-only 409
from shared.providers.serverless_git_provider import ServerlessGitError  # SERVERLESS-AUTOMERGE-SHA RT F4

try:
    from requests import RequestException as _RequestException
except ImportError:  # requests is a gateway dependency; without it the provider raises ServerlessGitError itself
    class _RequestException(Exception):  # type: ignore[no-redef]
        """Placeholder: never raised when requests is absent."""

# RT F4: what the capability probe may fail with and still be "keep the approval" (provider / transport errors).
_SOURCE_CHECK_PROBE_ERRORS = (ServerlessGitError, _RequestException, OSError)
import workflow_gates as _wf_gates
import intake_policy as _intake_policy  # lane 14 PR-4: exact source_channel allow-set (row L14-j)
from shared import build_admission as _build_admission  # BUILD-ADMISSION-QUEUE (G4)
import workflow_executions as _wfx  # BUILD-ADMISSION-QUEUE RT F3a (byte-identical copy of the Control Center's)
from qa_auditor import DualLensAuditorCoordinator, LensUnavailableError
from qa_auditor import judge as _qa_judge
from qa_auditor.coordinator import STAGE_TWO_DEADLINE_S
from qa_auditor import judge_input as _qa_judge_input
from qa_auditor.judge_input import IAC_MODE_GENERATE, IAC_MODE_OFF, build_judge_input
from qa_auditor.platform_facts import build_platform_facts
from qa_source import (BranchFetchError, BranchMovedError, BranchNotFoundError, EmptyArchiveError,
                       GitServerUnreachable, backend_for, fetch_tree_at_head, is_commit_sha)
from release_gatekeeper import (
    evaluate_release_decision,
    generate_release_certificate,
    post_release_certificate_to_vcs,
)
import qa_job_client as _qa_job_client_mod
import stage_deadline   # STAGE-DEADLINE (owner 11-13): one deadline mechanism for every agent stage
from stage_deadline import StageMode
import stage_jobs   # LONG-STAGE-CALLBACK + STAGE-JOB-RUNNER (owner 11-13): architect / developer / QA as callback jobs

try:
    from shared.callbacks import (CallbackDeliveryClient, guaranteed_callback_scope, has_undelivered_stage,
                                  redeliver_undelivered_callbacks)
    from shared.logging_utils import AgentLifecycle
except ImportError:
    from shared.callbacks import (CallbackDeliveryClient, guaranteed_callback_scope, has_undelivered_stage,
                                  redeliver_undelivered_callbacks)
    from shared.logging_utils import AgentLifecycle

try:
    from shared.quota_inspector import (CloudQuotaInspector, QuotaRegionsUnavailable, approved_quota_regions,
                                        sanitize_quota_for_prompt)
except ImportError:
    try:
        from apps.orchestrator_gateway.shared.quota_inspector import (CloudQuotaInspector, QuotaRegionsUnavailable,
                                                                      approved_quota_regions,
                                                                      sanitize_quota_for_prompt)
    except ImportError:
        try:
            from quota_inspector import (CloudQuotaInspector, QuotaRegionsUnavailable, approved_quota_regions,
                                         sanitize_quota_for_prompt)
        except ImportError:
            CloudQuotaInspector = None
            QuotaRegionsUnavailable = None
            approved_quota_regions = None
            sanitize_quota_for_prompt = None

logger = logging.getLogger("orchestrator-gateway-service")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="StackVend Orchestrator Gateway Service",
    description="Bridge connecting Cloud Workflows, Agent Personas (Vertex AI), and MCP Tool Servers.",
    version="1.0.0",
)


@app.exception_handler(UnsafePathError)
async def _unsafe_path_handler(request: Request, exc: UnsafePathError):
    # FD-4G: request-, LLM- or repo-supplied key failed structural path validation at a sink.
    logger.warning(f"Rejected unsafe path input on {request.url.path}: {exc.value!r} ({exc.reason})")
    return JSONResponse(status_code=400, content={"detail": f"unsafe path: {exc.reason}"})


@app.exception_handler(GateError)
async def _gate_error_handler(request: Request, exc: GateError):
    # FD-4F (D5): every gate failure carries a machine-readable error_class. Only CODE_DEFECT may loop back to the
    # developer; GATE_UNAVAILABLE / PLATFORM_DEFECT stop the run (non-2xx -> workflow `except` -> DLQ).
    logger.error(f"Gate failure on {request.url.path}: {exc.error_class.value} {exc.reason or ''}: {exc.message}")
    return JSONResponse(status_code=exc.http_status, content=exc.to_body())


db = None
try:
    from google.cloud import firestore
    _pid = os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT") or ""
    if not _pid:
        logger.warning("PROJECT_ID is unset. GCP client libraries will rely on default Application Credentials.")
    db = firestore.Client(project=_pid) if _pid else None
except Exception:
    db = None

developer_agent = DeveloperAgent(
    location=os.getenv("GEMINI_LOCATION") or os.getenv("VERTEX_LOCATION", "global")
)


# ------------------------------------------------------------------------------
# FD-4F: injectable gate dependencies (tests override these; nothing reads TEST_MODE)
# ------------------------------------------------------------------------------
_qa_client_cache: Dict[str, Any] = {}


def get_qa_job_client() -> Optional[Any]:
    """The isolated QA job client, or None when QA_* config is absent (-> GATE_UNAVAILABLE, never a pass)."""
    if "client" not in _qa_client_cache:
        try:
            _qa_client_cache["client"] = _qa_job_client_mod.build_default_client()
        except Exception as e:
            logger.error(f"QA job client could not be constructed: {type(e).__name__}: {e}")
            return None
    return _qa_client_cache["client"]


def get_source_backend_factory():
    """Returns product_id -> commit-bound source backend (GitHub REST or Serverless Git archive)."""
    return lambda product_id: backend_for(developer_agent, product_id)


def get_evidence_db() -> Any:
    """Firestore client used for QA evidence (qa_test_runs) and context reads; None -> gates fail closed."""
    return db


def get_governance_db() -> Any:
    """Firestore client for lane 17's workflow gates (kill switch, pre-build gate, approvals, resume, DEPLOY_ONLY).
    None (no PROJECT_ID / client construction failed) -> every gate answers 503 GATE_UNAVAILABLE, never a pass."""
    return db


# Lane 17 PR-2: the workflow refuses to run against a gateway whose contract is older (plan section 2.4).
# LONG-STAGE-CALLBACK (owner 11-13): 3 = the stage-job routes (/agent/architect/decompose-job,
# /agent/developer/execute-job, /agent/qa/verify-job) exist; the workflow that awaits them requires >= 3.
WORKFLOW_CONTRACT_VERSION = 3


def qa_configured() -> bool:
    return _qa_job_client_mod.QAJobConfig.from_env() is not None


def assert_pipeline_gates_ready() -> None:
    """FD-4F (D12): refuse to serve on Cloud Run if a gate is missing or the revision runs in test mode.
    QA job config is deliberately NOT required here: its absence is a per-request GATE_UNAVAILABLE, so a boot
    refusal never leaves an older (fail-open) revision serving. G1: also run by every stage-runner job execution
    before its stage (stage_runner.run), where Cloud Run sets CLOUD_RUN_JOB instead of K_SERVICE."""
    if not runtime_env.on_cloud_run():
        return
    if "TEST_MODE" in os.environ:
        raise RuntimeError("FD-4F: TEST_MODE must not be set on a Cloud Run revision or stage-runner job")
    for name, obj in (
        ("DualLensAuditorCoordinator", DualLensAuditorCoordinator),
        ("evaluate_release_decision", evaluate_release_decision),
        ("fetch_tree_at_head", fetch_tree_at_head),
    ):
        if obj is None:
            raise RuntimeError(f"FD-4F: pipeline gate {name} is unavailable")
    from gatekeeper_agent.verifier import SynthesisVerifierAgent  # noqa: F401  (import failure = boot failure)


@app.on_event("startup")
def _fd4f_startup_gate_check() -> None:
    assert_pipeline_gates_ready()


@app.on_event("startup")
def _argon_compat_startup_check() -> None:
    """Argon compat (owner 10-14): the env model fallback must have request rules, and a thinking-level model
    (gemini-4-argon, gemini-4-carbon) needs an SDK with ThinkingConfig.thinking_level; else UNSUPPORTED_MODEL_CONFIG
    at boot, never at a live call. Admin model settings are validated where they are saved/loaded (shared/settings.py).
    GEMINI-4-CARBON (owner 11-10): every level family in the table is checked, not only Argon's.
    DEFAULT-MODEL-GEMINI-4-CARBON (owner 11-11): the code defaults (gemini-4-carbon, fallbacks DEFAULT_FALLBACK_MODELS)
    are the models every new install runs, so they fail the boot loudly like the env model; the other level
    families are only logged (they matter once an admin selects one, and the settings save is their gate)."""
    from google.genai import types as genai_types
    from shared.gemini_model_config import (DEFAULT_FALLBACK_MODELS, DEFAULT_PRIMARY_MODEL, MODEL_FAMILIES,
                                            ThinkingControl, assert_sdk_supports_families)
    assert_sdk_supports_families([os.getenv("GEMINI_MODEL", ""), DEFAULT_PRIMARY_MODEL, *DEFAULT_FALLBACK_MODELS],
                                 types=genai_types)
    level_ids = [m for m, fam in MODEL_FAMILIES.items() if fam.thinking is ThinkingControl.LEVEL]
    try:
        assert_sdk_supports_families(level_ids, types=genai_types)
    except Exception as e:  # noqa: BLE001 - only matters once an admin selects a level model; settings save is the gate
        logger.error(f"{e}: {', '.join(level_ids)} calls would run with the model's default thinking")


# Step 1 S1-B (register HS-03/HS-05/HS-06): the developer stage's hallucination-stack runtime -- per-trace repair
# ledger and IaC provenance in Firestore, V1b against the terraform server's /validate (ID token, URL resolved at
# call time). Attached to this agent instance (no TEST_MODE branch, no process-global side effect at import).
from developer_agent.errors import DeveloperStageError  # noqa: E402  (lane 14 PR-0b RT F2)
# SLOW-CALL-FALLBACK (owner 11-13): the two typed outcomes of the developer's per-call timeout / fallback walk
from developer_agent.llm_transport import LlmFallbackExhausted, LlmStageBudgetExhausted  # noqa: E402
from developer_agent.qa_repair import JUDGE_FINDING_FIELD as _QA_JUDGE_FINDING_FIELD  # noqa: E402  (QA-JUDGE-STAMP)
from developer_agent.iac_intent_contract import RENDER_PATH as _QA_INTENT_RENDER_PATH  # noqa: E402  (RT F5)
from developer_agent.qa_repair import (JUDGE_REMOVALS_FIELD as _QA_JUDGE_REMOVALS_FIELD,  # noqa: E402
                                      INTENT_PATH as _QA_INTENT_PATH,   # JUDGE-NAMED-INTENT-REMOVAL
                                      judge_named_intent_removals as _qa_judge_named_intent_removals)
from developer_agent.qa_repair import (QA_REASON_FIELD as _QA_REASON_FIELD,  # noqa: E402  (QA-STAGE2-ONLY-REPAIR)
                                      STAGE2_FAILED_REASON as _QA_STAGE2_FAILED)
from developer_agent.qa_repair import is_judge_finding as _qa_is_judge_finding  # noqa: E402
from developer_agent.qa_repair import DRAFT_PATHS_FIELD as _QA_DRAFT_PATHS_FIELD  # noqa: E402  (SAT-49)
from developer_agent.qa_repair import BASE_HEAD_SHA_FIELD as _QA_BASE_HEAD_SHA_FIELD  # noqa: E402  (RT14-13)
from developer_agent.qa_repair import (COMMITTED_PATHS_FIELD as _QA_COMMITTED_PATHS_FIELD,  # noqa: E402
                                      ORPHAN_DELETIONS_FIELD as _QA_ORPHAN_DELETIONS_FIELD)  # (QA-REPAIR-KEEPS-ORPHAN-DELETIONS)
from developer_agent.deploy_repair import (DRAFT_PATHS_KWARG as _DEPLOY_DRAFT_PATHS_KWARG,  # noqa: E402  (SAT-49)
                                           DRAFT_PATHS_MAX as _DRAFT_PATHS_MAX, draft_paths_of as _draft_paths_of)
from developer_agent.lead_orchestrator import spec_rules_out_solo_fast_path  # noqa: E402  (RESUME-DEVELOPER-TASK-DAG)
from developer_agent.runtime_pin import PLATFORM_PYTHON_VERSION, platform_runtime_pins  # noqa: E402  (QA-JUDGE-FILE-MAPPING)
from developer_agent.hallucination_runtime import HallucinationRuntime  # noqa: E402
from developer_agent.app_provenance import FirestoreAppProvenanceStore  # noqa: E402  (SAT-49 F4)
from developer_agent.stack_clients import (FirestoreFactsProvider, FirestoreLedgerStore,  # noqa: E402
                                           FirestoreProvenanceStore, HttpValidateClient)

def _iac_intent_generate_setting(project_id: Optional[str] = None) -> bool:
    """TI-3h: governance.iac_intent_generate on a strict read; False when it is not exactly True or unreadable."""
    from shared.settings import iac_intent_generate_enabled
    return iac_intent_generate_enabled(project_id=project_id or os.getenv("PROJECT_ID") or None)


developer_agent.attach_stack_runtime(HallucinationRuntime(
    ledger_store=FirestoreLedgerStore(db) if db is not None else None,
    provenance_store=FirestoreProvenanceStore(db) if db is not None else None,
    validate_client=HttpValidateClient(lambda: resolve_service_url("mcp-terraform-server")),
    source="gateway",
    # lane 11 near-term: IPAM network facts the workload IaC must reference (POLICY.CIDR_LITERAL)
    facts_provider=FirestoreFactsProvider(db) if db is not None else None,
    # TI-3h: typed infrastructure (generate mode) is switched per install from Control Center Settings
    intent_generate_setting=_iac_intent_generate_setting,
    # SAT-49 F4: app-code provenance; a relaunch deletes the earlier build's unchanged orphan files
    app_provenance_store=FirestoreAppProvenanceStore(db) if db is not None else None,
))

# ------------------------------------------------------------------------------
# Request Models
# ------------------------------------------------------------------------------
class ArchitectDecomposeRequest(BaseModel):
    trace_id: Optional[str] = None
    spec_doc_id: Optional[str] = None
    product_id: Optional[str] = None
    source_channel: Optional[str] = "google_docs"
    spec_text: Optional[str] = None
    workspace_mcp_url: Optional[str] = None
    policy_matrix: Optional[Dict[str, Any]] = None
    human_feedback: Optional[str] = None
    quota_snapshot: Optional[Dict[str, Any]] = None


class DiscoveryQuotasRequest(BaseModel):
    project_id: Optional[str] = None
    regions: Optional[List[str]] = Field(default_factory=list)
    force_refresh: Optional[bool] = False


class ValidateHeadroomRequest(BaseModel):
    project_id: Optional[str] = None
    # FD-4AL: "" / absent = the workload region (platform setting `orchestration.default_gcp_region`, resolved by
    # developer_agent.terraform_engine.resolve_workload_region), never a literal region.
    # FD-7M-a (owner OQ-26): with a pipeline store, the workload's recorded region wins; a different value here (the
    # architect plan's target_region) is ignored and logged with both values.
    target_region: Optional[str] = None
    architecture_spec: Optional[Dict[str, Any]] = None
    bill_of_materials: Optional[Dict[str, int]] = None
    trace_id: Optional[str] = None


class ReleaseQuotaClaimRequest(BaseModel):
    claim_id: Optional[str] = None
    trace_id: Optional[str] = None



class DeveloperExecuteRequest(BaseModel):
    trace_id: Optional[str] = None
    product_id: str
    callback_url: Optional[str] = None
    spec_text: Optional[str] = None
    task_dag: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    retry_count: Optional[int] = 0
    tf_retry_count: Optional[int] = 0
    tf_remediation_context: Optional[str] = None
    # TI-5-R3: the deploy's typed validation_report (tf-applier callback, source "apply") on a terraform remediation
    # dispatch; absent (older workflow / tf-applier) = today's path. Read by developer_agent/deploy_repair.py.
    tf_validation_report: Optional[Dict[str, Any]] = None
    plan_markdown: Optional[str] = None
    plan_file_path: Optional[str] = None
    # FD-4R R-6: legacy ingress fields, still accepted (older workflows send them) and IGNORED: the developer's
    # ingress comes only from the persisted compliance decision (_resolve_developer_compliance_decision).
    domain_restricted_sharing: Optional[bool] = None
    allowed_domains: Optional[List[str]] = Field(default_factory=list)
    allow_unauthenticated: Optional[bool] = None
    enable_direct_iap: Optional[bool] = None
    # FD-4R R-6: the trace whose persisted compliance decision this run uses (a RESUME_DEVELOPER run sends the prior
    # FULL build's trace). Absent -> this run's trace_id, then the workload's last pre-build gate trace.
    compliance_trace_id: Optional[str] = None
    target_compute_services: Optional[List[str]] = Field(default_factory=list)
    # HD-01/HD-02: the architect's typed compute record (architect_agent.schemas.compute_intent_record); when absent
    # the developer reads pipeline_executions/{trace_id}.architect_compute_intent.
    architect_compute_intent: Optional[Dict[str, Any]] = None
    # Lane 19 L19-2 (FD-4I): the workload's AccessPolicy (shared/access_policy.py). Validated by the developer; when
    # absent the developer reads workloads/{pid}.access, else the compliance flags give the mode (never principals).
    access: Optional[Dict[str, Any]] = None
    # FD-4P (RT F12): no `github_repo` field. The repository is ONLY workloads/{product_id}.github_repo; no sender
    # ever passed the field, and a request-chosen repository let a caller commit, reconcile and open PRs anywhere.
    change_type: Optional[str] = None
    modules_to_upgrade: Optional[List[str]] = None
    author: Optional[str] = "Operator"

    @field_validator("task_dag", mode="before")
    @classmethod
    def _coerce_task_dag(cls, v):
        return v if v is not None else []

    @field_validator("compliance_trace_id", mode="before")
    @classmethod
    def _compliance_trace(cls, v):
        # A Firestore document id: validated like every gate trace id (FD-4G helper); empty = absent.
        return None if v in (None, "") else _fd4f_trace_id(v)


def _fd4f_trace_id(v: Any) -> str:
    # FD-4F (QA-5): trace_id is required on every gate and validated with FD-4G's helper. It keys the QA evidence
    # (qa_test_runs/{trace_id}) that the release gate reads, so a defaulted "auto-*-trace" can never match.
    return validate_trace_id(v)


def _fd4f_branch(v: Any) -> Any:
    if v is not None:
        validate_relpath(v)
    return v


def _fd4f_sha(v: Any) -> Any:
    if v is not None and not is_commit_sha(v):
        raise ValueError("expected_commit_sha must be a full 40-character lowercase hex git SHA")
    return v


class GatekeeperVerifyRequest(BaseModel):
    trace_id: str
    product_id: str
    branch_name: Optional[str] = None
    files: Optional[Dict[str, str]] = None
    # FD-55 W8 (register FD55-W8): accepted for older callers and not read; the gatekeeper's cure is archetype-free
    # (the workflow never sent it, so every stage ran with the "cloudrun" default before).
    archetype: Optional[str] = "cloudrun"
    # FD-4F / owner condition 19b: the exact paths THIS run committed (the developer's `files_committed`, i.e. the
    # tree the pre-commit cure produced). GK-5 judges only these, so stale uncured files that pre-exist in a
    # brownfield repo (or untouched services from earlier runs) cannot raise a false PLATFORM_DEFECT. Omitted ->
    # GK-5 falls back to the whole committed tree (stricter; the pre-lane-17 workflow does not send it).
    committed_paths: Optional[List[str]] = Field(default=None, max_length=10_000)

    @field_validator("trace_id")
    @classmethod
    def _v_trace(cls, v):
        return _fd4f_trace_id(v)

    @field_validator("branch_name")
    @classmethod
    def _v_branch(cls, v):
        return _fd4f_branch(v)

    @field_validator("committed_paths")
    @classmethod
    def _v_committed_paths(cls, v):
        if v is not None:
            for p in v:
                validate_relpath(p, reserved=GIT_RESERVED)
        return v

    @field_validator("files")
    @classmethod
    def _v_files(cls, v):
        # FD-4G: request-supplied manifest keys must be contained, canonical relpaths with no .git component.
        if v is not None:
            validate_manifest_keys(v, reserved=GIT_RESERVED)
        return v


class QAVerifyRequest(BaseModel):
    trace_id: str
    product_id: str
    branch_name: str
    # FD-4F (D7): the commit the gatekeeper verified; QA refuses if the branch head moved since.
    expected_commit_sha: Optional[str] = None
    # FD-4F (F3): workflow retry counter; recorded with the evidence and used for the no-progress stop.
    attempt: int = Field(default=0, ge=0, le=100)
    # FD-4F (F9, lane 13 code RT C7): the architect/compliance Task DAG the adherence judge audits against. Nothing
    # persists it to pipeline_executions/{trace}.stages.architect.details on castor (only architect_consensus is
    # written), so the workflow sends it here; a persisted DAG still wins. No DAG at all -> GATE_UNAVAILABLE.
    task_dag: Optional[List[Dict[str, Any]]] = Field(default=None, max_length=1000)

    @field_validator("trace_id")
    @classmethod
    def _v_trace(cls, v):
        return _fd4f_trace_id(v)

    @field_validator("branch_name")
    @classmethod
    def _v_branch(cls, v):
        return _fd4f_branch(v)

    @field_validator("expected_commit_sha")
    @classmethod
    def _v_sha(cls, v):
        return _fd4f_sha(v)



class AsyncQAVerifyRequest(QAVerifyRequest):
    callback_url: str


# LONG-STAGE-CALLBACK: a stage job request = the synchronous route's request + the workflow's callback URL (validated
# by stage_jobs.submit with shared.callbacks.classify_callback_url) + a required, validated trace id (it keys the job).
class ArchitectDecomposeJobRequest(ArchitectDecomposeRequest):
    trace_id: str
    product_id: str = Field(..., min_length=1)
    callback_url: str

    @field_validator("trace_id")
    @classmethod
    def _v_trace(cls, v):
        return _fd4f_trace_id(v)


class DeveloperExecuteJobRequest(DeveloperExecuteRequest):
    trace_id: str
    callback_url: str

    @field_validator("trace_id")
    @classmethod
    def _v_trace(cls, v):
        return _fd4f_trace_id(v)


class ReleasePromoteRequest(BaseModel):
    # FD-4P (owner row 23): unknown fields are refused (422), so a stale sender's `auto_merge: true` can never be
    # silently read as a policy override. The workflow body is exactly the declared fields.
    model_config = ConfigDict(extra="forbid")

    trace_id: str
    spec_doc_id: Optional[str] = None
    product_id: str
    branch_name: str
    test_summary: Optional[str] = None
    # FD-4P (owner row 23): no `auto_merge` field (it overrode the workload's review policy without QA evidence).
    # `require_human_code_review` may only TIGHTEN the policy: True forces human review, False is refused (422).
    require_human_code_review: Optional[bool] = None
    expected_commit_sha: Optional[str] = None

    @field_validator("trace_id")
    @classmethod
    def _v_trace(cls, v):
        return _fd4f_trace_id(v)

    @field_validator("branch_name")
    @classmethod
    def _v_branch(cls, v):
        return _fd4f_branch(v)

    @field_validator("expected_commit_sha")
    @classmethod
    def _v_sha(cls, v):
        return _fd4f_sha(v)

    @field_validator("require_human_code_review")
    @classmethod
    def _v_review_only_tightens(cls, v):
        if v is False:
            raise ValueError("require_human_code_review may only be true (a request can never loosen review policy)")
        return v



class ApprovalCallbackRegistration(BaseModel):
    trace_id: Optional[str] = None
    product_id: str
    # Lane 17 AJ-7: required. An empty id used to write this execution's callback onto EVERY pending approval of the
    # product (including stale plan approvals), so approving any of them resumed this run into deploy.
    approval_id: str = Field(..., min_length=1, max_length=200)
    callback_url: str = Field(..., min_length=1)


class PlanApprovalRequest(BaseModel):
    trace_id: Optional[str] = None
    product_id: str
    callback_url: str
    plan_markdown: Optional[str] = None
    plan_file_path: Optional[str] = None
    task_dag: List[Dict[str, Any]] = Field(default_factory=list)
    cost_delta_monthly: Optional[Union[float, str]] = 0.0
    compliance_summary: Optional[str] = None
    rework_cycle: Optional[int] = 0

    @field_validator("cost_delta_monthly", mode="before")
    @classmethod
    def parse_cost_delta(cls, v: Any) -> float:
        if v is None:
            return 0.0
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str):
            cleaned = re.sub(r"[^\d.-]", "", v)
            try:
                return float(cleaned) if cleaned else 0.0
            except ValueError:
                return 0.0
        return 0.0


class PubSubMessage(BaseModel):
    data: str
    messageId: Optional[str] = None
    publishTime: Optional[str] = None


class PubSubPushEnvelope(BaseModel):
    message: PubSubMessage
    subscription: Optional[str] = None


# ------------------------------------------------------------------------------
# Health Check
# ------------------------------------------------------------------------------
@app.get("/health")
def health_check():
    _stage_switch = stage_jobs.stage_jobs_switch(_resolved_dependency(get_governance_db))
    return {
        "status": "healthy",
        "service": "orchestrator-gateway-service",
        "environment": os.getenv("ENVIRONMENT", "prod"),
        # FD-4F (F10): false until Stage A sets QA_* env; every QA call then fails closed (GATE_UNAVAILABLE).
        "qa_configured": qa_configured(),
        # Lane 17: the main_orchestrator PR-2 workflow requires >= 2 (kill switch, pre-build gate, resume, DEPLOY_ONLY
        # gate, approval-request routes) and stops at its first step when this is missing or lower.
        "workflow_contract": WORKFLOW_CONTRACT_VERSION,
        # RT F4 (STAGE-JOB-RUNNER): the workflow runs architect / developer / QA as stage-runner jobs only while this
        # is true; false = the synchronous routes exactly as before LONG-STAGE-CALLBACK (rollback = a gateway deploy).
        "stage_jobs_enabled": _stage_switch["enabled"],
        "stage_jobs_switch": _stage_switch["source"],   # N1: ENV | SETTING | DEFAULT | CACHED | ERROR
        "release": release_info.current_release(),  # FD-7C P3a: read-only, from this build's release.json
    }


@app.get("/agent/qa/readiness")
def qa_readiness(client: Any = Depends(get_qa_job_client), evidence_db: Any = Depends(get_evidence_db)):
    """FD-4F register row 19 option A: pipeline-START QA readiness check (zero LLM, zero vending, zero job runs).

    The workflow calls this before the architect / vending for every FULL_BUILD and RESUME_DEVELOPER run, so a run
    whose QA gate could never pass stops at $0 instead of after vending + the developer swarm. It checks exactly the
    configuration preconditions that `run_qa` refuses on at dispatch (the `/health.qa_configured` semantics, plus
    that the QA job client can actually be constructed and the evidence store exists), plus (row L3-PRB-r, one Run
    API GET cached 300 s) the job identity check, args == the sandbox_job entrypoint and the job contract label. It
    does NOT execute the QA job or call the judge. 200 = ready; 503 GATE_UNAVAILABLE reason=QA_NOT_CONFIGURED /
    QA_JOB_LOOKUP / QA_JOB_DRIFT / QA_JOB_NOT_READY = stop (DLQ).
    Contract: docs/handoff/wave2-lane13-report.md section "Pipeline-start QA readiness".
    """
    missing_env = [k for k in _qa_job_client_mod.QAJobConfig.REQUIRED_ENV if not (os.getenv(k) or "").strip()]
    missing = []
    if client is None:
        missing.append("qa_job_client")
    if evidence_db is None:
        missing.append("evidence_store")
    if missing:
        raise GateUnavailableError(
            f"QA is not ready ({', '.join(missing)}); the run stops before vending instead of at the QA gate",
            reason="QA_NOT_CONFIGURED",
            details={"missing": missing, "missing_env": missing_env},
        )
    # Row L3-PRB-r: also prove the job can run the PR-B contract (identity, args, contract label), so a job whose image
    # predates PR-B or drifted stops here at $0 (503 QA_JOB_DRIFT / QA_JOB_LOOKUP / QA_JOB_NOT_READY), not after
    # vending + swarm + gatekeeper. Anything unexpected is not-ready too (fail closed, typed).
    try:
        client.verify_job_readiness()
    except GateError:
        raise
    except Exception as e:
        raise GateUnavailableError(f"QA job readiness check failed: {type(e).__name__}", reason="QA_JOB_LOOKUP") from e
    return {"status": "READY", "ready": True, "qa_configured": True, "evidence_store": True}


# ------------------------------------------------------------------------------
# STAGE-DEADLINE (owner 11-13): every agent stage the workflow calls runs under one StageDeadline (stage_deadline.py)
# ------------------------------------------------------------------------------
def _resolved_dependency(dep: Any) -> Any:
    """A FastAPI dependency's value outside a request (test overrides respected)."""
    return app.dependency_overrides.get(dep, dep)()


def _stage_liveness_probe(trace_id: Optional[str], *, execution_id: Optional[str] = None,
                          stage_job: Optional[Tuple[str, str]] = None):
    """The run-liveness probe of a stage (stage_deadline.run_probe): run ended, superseded, emergency stop.
    None when there is no store or no valid trace id (the deadline alone bounds the stage)."""
    gdb = _resolved_dependency(get_governance_db)
    if gdb is None or not trace_id:
        return None
    try:
        trace = validate_trace_id(trace_id)
    except Exception:  # noqa: BLE001 - an id that is not a document id has no run record to read
        return None
    return stage_deadline.run_probe(gdb, trace, execution_id=execution_id, stage_job=stage_job,
                                    kill_switch=lambda: _read_kill_switch(gdb)["active"])


def _run_stage(stage: str, mode: StageMode, trace_id: Optional[str], product_id: Optional[str],
               body: Callable[[], Any], *, execution_id: Optional[str] = None,
               stage_job: Optional[Tuple[str, str]] = None) -> Any:
    """Runs one stage body under its STAGE_BUDGETS deadline. In time: the body's answer, unchanged. Late: 504
    STAGE_DEADLINE_EXCEEDED (typed; the workflow keeps the class). Nothing is written after the answer."""
    sd = stage_deadline.StageDeadline(stage_deadline.budget_for(stage, mode), trace_id=trace_id,
                                      product_id=product_id,
                                      probe=_stage_liveness_probe(trace_id, execution_id=execution_id,
                                                                  stage_job=stage_job))
    return stage_deadline.run_with_deadline(sd, body)


def _http_answer(fn: Callable[[], Any]) -> stage_jobs.Answer:
    """(status, JSON body) exactly as the synchronous route answers: the route's result (200, or its own response),
    a GateError through _gate_error_handler's body, an HTTPException as FastAPI's {"detail": ...}, an unsafe path as
    _unsafe_path_handler's 400. Anything else propagates (stage_jobs answers it 500 UNHANDLED, typed)."""
    try:
        result = fn()
    except GateError as exc:
        logger.error(f"Gate failure (stage job): {exc.error_class.value} {exc.reason or ''}: {exc.message}")
        return exc.http_status, jsonable_encoder(exc.to_body())
    except HTTPException as exc:
        return exc.status_code, {"detail": jsonable_encoder(exc.detail)}
    except UnsafePathError as exc:
        logger.warning(f"Rejected unsafe path input (stage job): {exc.value!r} ({exc.reason})")
        return 400, {"detail": f"unsafe path: {exc.reason}"}
    if isinstance(result, Response):
        return result.status_code, json.loads(result.body or b"null")
    return 200, jsonable_encoder(result)


def _job_answer(stage: str, job: "stage_jobs.StageJob", body: Callable[[], Any]) -> stage_jobs.Answer:
    """One stage job's answer: the stage body under the stage's CALLBACK deadline counted from the job's accepted_at
    (STAGE-JOB-RUNNER, RT §6.4), with the job's liveness probe (run ended, another execution owns the trace, a newer
    job owns the stage, emergency stop)."""
    sd = stage_deadline.StageDeadline(stage_deadline.budget_for(stage, StageMode.CALLBACK), trace_id=job.trace_id,
                                      product_id=job.product_id,
                                      probe=_stage_liveness_probe(job.trace_id, execution_id=job.execution_id,
                                                                  stage_job=(stage, job.job_id)),
                                      elapsed_s=max(0.0, time.time() - job.accepted_at))
    job.deadline = sd
    return _http_answer(lambda: stage_deadline.run_with_deadline(sd, body))


def get_stage_job_starter() -> Callable[["stage_jobs.StageJob"], str]:
    """STAGE-JOB-RUNNER: starts one stage-runner execution (Cloud Run Admin API, the gateway's identity). The
    gateway's own release goes with it, so the job refuses to run a stage on a different build (skew check)."""
    return stage_jobs.run_api_starter(os.getenv("PROJECT_ID", ""), os.getenv("REGION", ""),
                                      expected_release=stage_jobs.release_token(release_info.current_release()))


def get_stage_execution_reader() -> Callable[[str], Dict[str, Any]]:
    """STAGE-JOB-RUNNER: reads one stage-runner execution (run.executions.get on that job)."""
    return stage_jobs.run_api_execution_reader()


def _submit_stage_job(stage: str, req: Any) -> Dict[str, Any]:
    """The job routes: the request is validated here (same model as before), stored by reference, and one
    stage-runner execution is started; 202 only once it exists (stage_jobs.submit)."""
    return stage_jobs.submit(stage, trace_id=req.trace_id, product_id=req.product_id, callback_url=req.callback_url,
                             request=req.model_dump(mode="json"), db=_resolved_dependency(get_governance_db),
                             start=_resolved_dependency(get_stage_job_starter))


def stage_job_body(stage: str, request: Dict[str, Any]) -> Callable[[], Any]:
    """STAGE-JOB-RUNNER (inside the job): the stored request rebuilt with the job route's own model and the SAME
    stage body as the synchronous route; QA's dependencies are built here exactly as FastAPI builds them."""
    if stage == "architect":
        a_req = ArchitectDecomposeJobRequest(**request)
        return lambda: _architect_decompose_body(a_req)
    if stage == "developer":
        d_req = DeveloperExecuteJobRequest(**request)
        return lambda: _developer_execute_body(d_req)
    if stage == "qa":
        q_req = AsyncQAVerifyRequest(**request)
        return lambda: _qa_verify_body(q_req, _resolved_dependency(get_qa_job_client),
                                       _resolved_dependency(get_source_backend_factory),
                                       _resolved_dependency(get_evidence_db), mode="CALLBACK JOB")
    raise ValueError(f"{stage!r} is not a callback stage")


def run_stage_job_here(job: "stage_jobs.StageJob", request: Dict[str, Any]) -> stage_jobs.Answer:
    """STAGE-JOB-RUNNER (inside the job): the job's (status, body), exactly the synchronous route's answer."""
    return _job_answer(job.stage, job, stage_job_body(job.stage, request))


@app.get("/agent/stage-job/state")
def stage_job_state(trace_id: str, stage: str, job_id: str):
    """STAGE-JOB-RUNNER: the workflow's probe between await slices. DEAD = the job can no longer answer (its
    execution ended without an answer, or its answer was undeliverable); never DEAD on a read error."""
    trace = validate_trace_id(trace_id)
    if stage not in stage_jobs.JOB_STAGES or len(job_id) != 32 or not all(c in "0123456789abcdef" for c in job_id):
        raise HTTPException(status_code=400, detail="unknown stage or malformed job id")
    gdb = _resolved_dependency(get_governance_db)
    if gdb is None:
        return {"state": "UNKNOWN", "reason": "STORE_UNAVAILABLE"}
    return stage_jobs.job_state(gdb, trace, stage, job_id, _resolved_dependency(get_stage_execution_reader))


# ------------------------------------------------------------------------------
# Agent Execution Endpoints (Invoked by Cloud Workflows)
# ------------------------------------------------------------------------------
@app.post("/agent/architect/decompose")
def architect_decompose(req: ArchitectDecomposeRequest):
    """Step 1 (synchronous form): the architect under its SYNC stage deadline (STAGE-DEADLINE)."""
    return _run_stage("architect", StageMode.SYNC, req.trace_id, req.product_id,
                      lambda: _architect_decompose_body(req))


@app.post("/agent/architect/decompose-job", status_code=status.HTTP_202_ACCEPTED)
def architect_decompose_job(req: ArchitectDecomposeJobRequest):
    """Step 1 (LONG-STAGE-CALLBACK): 202 once the stage-runner execution exists; the answer arrives on
    `callback_url`."""
    return _submit_stage_job("architect", req)


def _architect_decompose_body(req: ArchitectDecomposeRequest):
    """
    Invoked by Step 1 of castor_main_orchestrator workflow.
    Executes Architect Agent reasoning to parse spec and return Task DAG.
    """
    feature_tag = req.trace_id or req.product_id
    logger.info("=" * 64)
    logger.info(f"🚀 FEATURE [{feature_tag}] BEGIN PROCESS: {req.product_id}")
    logger.info("=" * 64)

    with AgentLifecycle("Architect", req.product_id or "default", req.trace_id or "auto-trace", mode="SYNC") as agent:
        try:
            try:
                from architect_agent.handler import ArchitectAgent
            except ImportError:
                from handler import ArchitectAgent

            agent_inst = ArchitectAgent(
                project_id=os.getenv("PROJECT_ID", ""),
                location=os.getenv("GEMINI_LOCATION") or os.getenv("VERTEX_LOCATION", "global"),
            )
            workspace_url = req.workspace_mcp_url or os.getenv("WORKSPACE_MCP_URL", "")
            # PLAN-CONTRACT-CHECK: the plan contract's root `cloudbuild.yaml` clause needs the workload's VCS kind
            # (None when unreadable: that clause is then skipped and recorded, never guessed).
            vcs_kind = _architect_vcs_kind(req.product_id)

            result = agent_inst.decompose(
                spec_text=req.spec_text,
                spec_doc_id=req.spec_doc_id,
                product_id=req.product_id,
                trace_id=req.trace_id,
                source_channel=req.source_channel or "google_docs",
                workspace_mcp_url=workspace_url,
                policy_matrix=req.policy_matrix,
                human_feedback=req.human_feedback,
                quota_snapshot=req.quota_snapshot,
                vcs_kind=vcs_kind,
            )

            agent.set_summary(
                f"Decomposed {len(result.task_dag)} tasks. Approval required: {result.architecture_plan.requires_human_approval}",
                status="SUCCESS",
            )
            return {
                "status": "SUCCESS",
                "trace_id": result.trace_id,
                "product_id": result.product_id,
                "task_dag": [t.model_dump() for t in result.task_dag],
                "infra_plan": result.infra_plan,
                "markdown_summary": result.markdown_summary,
                "requires_human_approval": result.architecture_plan.requires_human_approval,
                "risk_assessment": result.architecture_plan.risk_assessment,
                "plan_markdown": result.plan_markdown,
                "plan_file_path": result.plan_file_path,
                "architecture_plan": result.architecture_plan.model_dump(),
                "architect_compute_intent": result.compute_intent,
                "architect_consensus": result.consensus_telemetry.model_dump() if hasattr(result.consensus_telemetry, "model_dump") else (result.consensus_telemetry if isinstance(result.consensus_telemetry, dict) else None),
            }
        except GateError as e:
            # AH-2 / AH-5: typed outcome (ARCHITECT_RATE_LIMITED 503, SPEC_FETCH_FAILED 502) -> _gate_error_handler
            # returns its error_class/reason body; the workflow's architect `except` routes it to the DLQ.
            agent.set_summary(f"Architect decomposition failed: {e.reason or e.error_class.value}: {e}", status="FAILED")
            raise
        except Exception as e:
            agent.set_summary(f"Architect decomposition failed: {str(e)}", status="FAILED")
            logger.error(f"Architect decomposition failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))


# ------------------------------------------------------------------------------
# Google Cloud Quotas & Capacity Feasibility Endpoints (Step 0 & Pre-Dev Gate)
# ------------------------------------------------------------------------------
@app.post("/discovery/quotas")
def discovery_quotas(req: DiscoveryQuotasRequest):
    """
    Invoked by Step 0 of castor_main_orchestrator workflow.
    Returns regional and global quota headroom snapshot with caching.
    """
    project_id = req.project_id or os.getenv("PROJECT_ID", "")
    inspector = CloudQuotaInspector(db_client=db) if CloudQuotaInspector else None
    if not inspector:
        return {"status": "DEGRADED", "project_id": project_id, "regions": {}, "global": {}, "active_claims": {}}

    # FD-7M-a: the request's regions (the workflow's fixed list, main_orchestrator.yaml harvest_project_quotas) plus
    # every approved deployable region (Settings), so a workload in an added region gets its snapshot without a
    # workflow change (POST-RC-NO-CORE-TF). On the default install the approved list is already in the request:
    # the same regions in the same order as before. No region at all -> the approved list (never a fixed list).
    regions = _quota_harvest_regions(req.regions or [])
    snapshot = inspector.harvest_quota_snapshot(
        project_id=project_id,
        regions=regions,
        force_refresh=req.force_refresh or False,
    )
    return snapshot


def _quota_harvest_regions(requested: List[str]) -> List[str]:
    """FD-7M-a: `requested` (order kept) followed by each approved deployable region not already in it. The approved
    list is read with the gateway's Firestore client. Unreadable: with requested regions, those are harvested and the
    typed line is logged (SAT-23 RT F3: the snapshot is advisory input to the architect); with none, 503
    REGION_UNAVAILABLE (the workflow's harvest step then continues without a snapshot, logged). No client (local runs
    without a pipeline store) -> the requested regions as given."""
    regions = [r for r in requested if isinstance(r, str)]
    if db is None or approved_quota_regions is None:
        return regions
    try:
        approved = approved_quota_regions(db)
    except QuotaRegionsUnavailable as region_err:
        if regions:
            logger.warning(f"REGION_UNAVAILABLE: approved deployable regions not harvested ({region_err}); "
                           f"harvesting the requested {regions}")
            return regions
        raise HTTPException(status_code=503, detail=f"REGION_UNAVAILABLE: {region_err}")
    return regions + [r for r in approved if r not in regions]


def _quota_gate_product_id(gdb: Any, trace_id: Optional[str], project_id: str) -> str:
    """FD-7M-a (owner OQ-26): the product whose quota is checked: pipeline_executions/{trace_id}.product_id, else the
    one workloads record whose project_id is the request's. None or several, or an unreadable store -> 503
    REGION_UNAVAILABLE (the workflow's "unverified != valid" pause; the region is never guessed)."""
    if trace_id:
        try:
            snap = gdb.collection("pipeline_executions").document(trace_id).get()
            data = snap.to_dict() if getattr(snap, "exists", None) is True else None
        except Exception as read_err:  # noqa: BLE001 - unreadable store = region unknown (typed)
            raise HTTPException(status_code=503, detail=f"REGION_UNAVAILABLE: pipeline_executions/{trace_id} "
                                                        f"unreadable ({type(read_err).__name__})")
        product_id = data.get("product_id") if isinstance(data, dict) else None
        if isinstance(product_id, str) and product_id:
            return product_id
    if not project_id:
        raise HTTPException(status_code=503, detail="REGION_UNAVAILABLE: no pipeline record and no project id to find "
                                                    "the workload whose region the quota check uses")
    try:
        owners = [d.id for d in gdb.collection("workloads").where("project_id", "==", project_id).limit(2).stream()]
    except Exception as read_err:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"REGION_UNAVAILABLE: workloads for project {project_id} "
                                                    f"unreadable ({type(read_err).__name__})")
    if len(owners) != 1:
        raise HTTPException(status_code=503, detail=f"REGION_UNAVAILABLE: {len(owners) or 'no'} workload records "
                                                    f"name project {project_id}; the workload region is unknown")
    return owners[0]


@app.post("/discovery/validate-headroom")
def discovery_validate_headroom(req: ValidateHeadroomRequest):
    """
    Invoked by Step 2.6 Pre-Developer Quota Gate of castor_main_orchestrator workflow.
    Validates BOM demand against regional headroom and active in-flight claims.
    If valid, records an in-flight claim to prevent TOCTOU race conditions.
    """
    project_id = req.project_id or os.getenv("PROJECT_ID", "")
    if db is not None:
        # FD-7M-a (owner OQ-26): the workload's recorded region (through the approved-regions helper) wins over the
        # request's target_region; a different request value is ignored and logged with both values.
        from developer_agent.terraform_engine import RegionNotApproved, RegionUnavailable, resolve_workload_region
        product_id = _quota_gate_product_id(db, req.trace_id, project_id)
        try:
            workload_region = resolve_workload_region(db, product_id=product_id, stage="quota_gate")
        except RegionUnavailable as region_err:   # unverified != valid (AJ-8): the workflow pauses for approval
            raise HTTPException(status_code=503, detail=f"REGION_UNAVAILABLE: {region_err}")
        except RegionNotApproved as not_approved:
            raise HTTPException(status_code=422, detail=f"REGION_NOT_APPROVED: {not_approved}")
        if req.target_region and req.target_region != workload_region:
            logger.warning(f"QUOTA_TARGET_REGION_IGNORED: '{product_id}' (trace {req.trace_id}): request target_region "
                           f"{req.target_region!r} ignored; the workload region is {workload_region!r}")
        req.target_region = workload_region
    elif not req.target_region:
        from developer_agent.terraform_engine import RegionUnavailable, resolve_workload_region
        try:
            req.target_region = resolve_workload_region(db)
        except RegionUnavailable as region_err:   # unverified != valid (AJ-8): the workflow pauses for approval
            raise HTTPException(status_code=503, detail=f"REGION_UNAVAILABLE: {region_err}")
    inspector = CloudQuotaInspector(db_client=db) if CloudQuotaInspector else None
    if not inspector:
        return {"status": "PASS", "is_valid": True, "target_region": req.target_region, "violations": []}

    snapshot = inspector.harvest_quota_snapshot(project_id=project_id, regions=[req.target_region])

    demand = req.bill_of_materials
    if not demand and req.architecture_spec:
        demand = inspector.estimate_bom_demand(req.architecture_spec)
    if not demand:
        demand = {"compute.googleapis.com/regional_external_ip_addresses": 0}

    is_valid, violations, details = inspector.validate_headroom(
        snapshot=snapshot,
        target_region=req.target_region,
        demand=demand,
        trace_id=req.trace_id,
    )

    claim_id = None
    if is_valid and req.trace_id:
        claim_id = inspector.create_in_flight_claim(
            project_id=project_id,
            region=req.target_region,
            demand=demand,
            trace_id=req.trace_id,
        )

    gcp_console_url = f"https://console.cloud.google.com/iam-admin/quotas?project={project_id}" if project_id else "https://console.cloud.google.com/iam-admin/quotas"

    return {
        "status": "PASS" if is_valid else "QUOTA_EXCEEDED",
        "is_valid": is_valid,
        "target_region": req.target_region,
        "claim_id": claim_id,
        "demand": demand,
        "violations": violations,
        "details": details,
        "remediation": {
            "gcp_console_url": gcp_console_url,
            "instructions": "Increase quota in Google Cloud Console or select an alternate healthy region.",
        } if not is_valid else None,
    }


@app.post("/events/quota-claim/release")
def release_quota_claim(req: ReleaseQuotaClaimRequest):
    """
    Releases an in-flight quota claim upon pipeline completion, failure, or cancellation.
    """
    inspector = CloudQuotaInspector(db_client=db) if CloudQuotaInspector else None
    released = False
    if inspector:
        released = inspector.release_in_flight_claim(claim_id=req.claim_id, trace_id=req.trace_id)
    return {"status": "SUCCESS", "released": released}



def _read_compliance_selection(ref: Any, product_id: str) -> Optional[str]:
    """The stored explicit selection (`workloads/{pid}.requested_compliance_profile`). Unreadable or corrupt ->
    GATE_UNAVAILABLE (never treated as "no selection")."""
    from compliance_agent import profiles as _cp

    try:
        snap = ref.get()
        data = (snap.to_dict() or {}) if getattr(snap, "exists", False) else {}
    except Exception as e:
        raise GateUnavailableError(
            f"could not read the stored compliance profile selection: {type(e).__name__}",
            reason="COMPLIANCE_UNAVAILABLE", details={"product_id": product_id},
        ) from e
    try:
        return _cp.parse_profile(data.get(_cp.REQUESTED_PROFILE_FIELD) if isinstance(data, dict) else None,
                                 where=f"workloads/{product_id}.{_cp.REQUESTED_PROFILE_FIELD}")
    except _cp.InvalidComplianceProfile as e:
        raise GateUnavailableError(str(e), reason="COMPLIANCE_UNAVAILABLE",
                                   details={"product_id": product_id, "error_class": e.error_class}) from e


def _store_compliance_selection(fs: Any, product_id: str, requested: str, *, requested_via: str,
                                trace_id: str = "") -> None:
    """Stores an explicit selection on the workload. Owner decision 10-18 (row CP-11): replacing a stored REGULATED
    selection by a less strict one (`profiles.is_downgrade`) is not stored: an admin approval card
    (approval_requests/appr-cpdown-{pid}-{from}-{to}, approval_type COMPLIANCE_PROFILE_DOWNGRADE) is created and the
    run is refused (409 OPERATOR_ACTION_REQUIRED) until an admin approves it in the Control Center, which then stores
    the new profile. Read/write failure -> GATE_UNAVAILABLE."""
    from compliance_agent import profiles as _cp

    ref = fs.collection("workloads").document(product_id)
    stored = _read_compliance_selection(ref, product_id)
    if _cp.is_downgrade(stored, requested):
        approval_id = _cp.downgrade_approval_id(product_id, stored, requested)
        try:
            from google.api_core import exceptions as gexc

            card = fs.collection("approval_requests").document(approval_id)
            try:
                card.create(_cp.downgrade_approval_record(
                    product_id, stored, requested, requested_via=requested_via, trace_id=trace_id,
                    now_iso=datetime.now(timezone.utc).isoformat(), now=time.time()))
            except gexc.AlreadyExists:
                pass  # one card per transition: PENDING keeps waiting, REJECTED keeps refusing
        except Exception as e:
            raise GateUnavailableError(
                f"could not create the compliance downgrade approval: {type(e).__name__}",
                reason="COMPLIANCE_UNAVAILABLE", details={"product_id": product_id},
            ) from e
        raise OperatorActionRequiredError(
            f"compliance profile downgrade {stored} -> {requested} for '{product_id}' needs an admin approval "
            f"({approval_id}); the run is refused until it is approved in the Control Center",
            reason=_cp.REASON_DOWNGRADE_APPROVAL,
            details={"product_id": product_id, "approval_id": approval_id, "from_profile": stored,
                     "to_profile": requested},
        )
    if stored == requested:
        return
    try:
        ref.set({_cp.REQUESTED_PROFILE_FIELD: requested}, merge=True)
    except Exception as e:
        raise GateUnavailableError(
            f"could not store the compliance profile selection: {type(e).__name__}",
            reason="COMPLIANCE_UNAVAILABLE", details={"product_id": product_id},
        ) from e


def _resolve_compliance_selection(fs: Any, product_id: str, raw: Any,
                                  trace_id: str = "") -> Tuple[Optional[str], Optional[str]]:
    """compliance-profile-explicit: (profile, origin) of the explicit compliance-profile selection.

    * `raw` (this run's `compliance_profile`) set -> it, exact vocabulary only (InvalidComplianceProfile -> 422), and it
      is stored on the workload so later runs (retrigger, SRE, refactor, deploy-only) keep it. A downgrade of a stored
      regulated selection needs an admin approval first (`_store_compliance_selection`, row CP-11);
    * else the selection stored on the workload (`workloads/{pid}.requested_compliance_profile`);
    * else (None, None): the compliance server answers STANDARD, recorded as DEFAULT_STANDARD.
    Fails closed: an unreadable/unwritable workload document or a corrupt stored value is GATE_UNAVAILABLE (a silent
    STANDARD would downgrade a regulated workload). With no Firestore client off Cloud Run (tests, local) only `raw` is
    used; on Cloud Run no client is GATE_UNAVAILABLE (RT F3)."""
    from compliance_agent import profiles as _cp

    requested = _cp.parse_profile(raw)
    if fs is None:
        if runtime_env.on_cloud_run():
            # RT F3: on Cloud Run a missing Firestore client would silently drop the stored selection (-> STANDARD).
            raise GateUnavailableError(
                "no Firestore client: the stored compliance profile selection cannot be read or written",
                reason="COMPLIANCE_UNAVAILABLE", details={"product_id": product_id, "failure": "NO_STORE"},
            )
        return (requested, _cp.SOURCE_EXPLICIT_REQUEST) if requested else (None, None)
    if requested:
        _store_compliance_selection(fs, product_id, requested, requested_via="pipeline", trace_id=trace_id)
        return requested, _cp.SOURCE_EXPLICIT_REQUEST
    stored = _read_compliance_selection(fs.collection("workloads").document(product_id), product_id)
    return (stored, _cp.SOURCE_WORKLOAD_SELECTION) if stored else (None, None)


def _read_workload_access_mode(fs: Any, product_id: str) -> Optional[str]:
    """ACCESS-INTERNAL-SERVICE-ADVISORY: the stored access mode (`workloads/{pid}.access.mode`, exact enum) the
    compliance stage's access advisory needs; None when the workload has no access record. No Firestore client
    (tests, local) -> None; on Cloud Run `_resolve_compliance_selection` has already refused a missing client.
    Unreadable -> GATE_UNAVAILABLE; a record that is not an object or a mode outside the enum -> PLATFORM_DEFECT (the
    developer would refuse the same record as ACCESS_POLICY_INVALID). Never "no record" for a record it cannot read."""
    from compliance_agent import access_advisory as _aa

    if fs is None:
        return None
    where = f"workloads/{product_id}.access"
    try:
        snap = fs.collection("workloads").document(product_id).get()
        data = (snap.to_dict() or {}) if getattr(snap, "exists", False) else {}
    except Exception as e:  # noqa: BLE001 - typed below
        raise GateUnavailableError(f"could not read {where} for the access advisory: {type(e).__name__}",
                                   reason=_aa.REASON_FACTS_UNAVAILABLE, stage=_aa.STAGE,
                                   details={"product_id": product_id}) from e
    try:
        return _aa.access_mode_of(data.get("access") if isinstance(data, dict) else None, where=where)
    except _aa.AccessAdvisoryError as e:
        raise PlatformDefectError(str(e), reason=_aa.REASON_FACTS_INVALID, stage=_aa.STAGE,
                                  details={"product_id": product_id}) from e


def _write_compliance_stage_failed(trace_id: str, err: GateError) -> None:
    """PRIVATE-INGRESS-EARLY-STOP: what the operator reads, for a typed failure of stage `compliance` (the stop, an
    unreadable compute record, a decision that could not be persisted). The Control Center's pipeline card and
    Flight Deck render `stages.<stage>.summary`, and the workflow has no FAILED write for this stage. Best effort and logged: the typed
    error still ends the run and carries the same text to pipeline_executions/{trace}.error."""
    if db is None or not trace_id:
        return
    try:
        db.collection("pipeline_executions").document(trace_id).set({"stages": {"compliance": {
            "status": "FAILED", "error_class": err.error_class.value, "summary": err.message}}}, merge=True)
    except Exception as e:  # noqa: BLE001 - visibility only; the run has already stopped typed
        logger.error(f"Compliance stage FAILED record for trace '{trace_id}' could not be written: {type(e).__name__}: {e}")


@app.post("/agent/compliance/audit")
def compliance_audit(req: Dict[str, Any]):
    """Step 1.5: the compliance audit under its SYNC stage deadline (STAGE-DEADLINE)."""
    return _run_stage("compliance", StageMode.SYNC, req.get("trace_id"), req.get("product_id"),
                      lambda: _compliance_audit_body(req))


def _compliance_audit_body(req: Dict[str, Any]):
    """
    Invoked by Step 1.5 of castor_main_orchestrator workflow.
    Audits initial Task DAG against Assured Workloads / regulatory requirements.
    Completes in <50ms for STANDARD workloads, or enriches DAG with CMEK / Audit Logging.
    """
    product_id = req.get("product_id", "default")
    trace_id = req.get("trace_id", "auto-trace")
    from compliance_agent.profiles import ComplianceProfileRefused, InvalidComplianceProfile

    with AgentLifecycle("Compliance", product_id, trace_id, mode="SYNC") as agent:
        try:
            from compliance_agent.handler import ComplianceAgentHandler
            from compliance_agent.schemas import ComplianceAuditRequest

            # compliance-profile-explicit: the explicit selection (this request, else the one stored on the workload).
            selected_profile, selection_origin = _resolve_compliance_selection(
                db, product_id, req.get("compliance_profile"), trace_id=trace_id)
            compliance_url = os.getenv("COMPLIANCE_SERVER_URL") or resolve_service_url("mcp-compliance-server")
            # FD-4F / owner 19f: a pipeline gate always requires the remote compliance server (no embedded fallback).
            # ACCESS-INTERNAL-SERVICE-ADVISORY: the stored access mode is read only when the decision is public.
            handler = ComplianceAgentHandler(
                compliance_server_url=compliance_url, require_remote_engine=True,
                workload_access_reader=lambda pid: _read_workload_access_mode(db, pid))
            audit_req = ComplianceAuditRequest(
                product_id=product_id,
                spec_text=req.get("spec_text", ""),
                task_dag=req.get("task_dag", []),
                folder_id=req.get("folder_id", ""),
                trace_id=trace_id,
                plan_markdown=req.get("plan_markdown"),
                plan_file_path=req.get("plan_file_path"),
                policy_matrix=req.get("policy_matrix"),
                compliance_profile=selected_profile,
                compliance_profile_origin=selection_origin,
            )
            res = handler.audit_and_enrich(audit_req)
            agent.set_summary(f"Profile: {res.compliance_profile}, Injected tasks: {len(res.injected_tasks)}", status="SUCCESS")
            return {
                "status": res.status,
                "product_id": res.product_id,
                "compliance_profile": res.compliance_profile,
                "is_regulated": res.is_regulated,
                "requires_cmek": res.requires_cmek,
                "requires_audit_logging": res.requires_audit_logging,
                "domain_restricted_sharing": res.domain_restricted_sharing,
                "allowed_domains": res.allowed_domains,
                "allow_unauthenticated": res.allow_unauthenticated,
                "enable_direct_iap": getattr(res, "enable_direct_iap", False),
                "enforce_private_ingress": getattr(res, "enforce_private_ingress", False),
                "task_dag": res.enriched_dag,
                "injected_tasks": res.injected_tasks,
                "compliance_summary": res.compliance_summary,
                "plan_markdown": res.plan_markdown,
                "plan_file_path": res.plan_file_path,
                "policy_matrix": getattr(res, "policy_matrix", None),
                "has_policy_conflicts": getattr(res, "has_policy_conflicts", False),
                "policy_conflicts": getattr(res, "policy_conflicts", []),
                "requires_human_approval": getattr(res, "requires_human_approval", False),
                "compliance_profile_source": getattr(res, "compliance_profile_source", None),
                "profile_advisories": list(getattr(res, "profile_advisories", None) or []),
                # ACCESS-INTERNAL-SERVICE-ADVISORY: travels in this body to the pre-build gate (`compliance`), which
                # copies it onto the plan approval card.
                "access_advisories": list(getattr(res, "access_advisories", None) or []),
                "access_advisories_omitted": int(getattr(res, "access_advisories_omitted", 0) or 0),
            }
        except InvalidComplianceProfile as ip:
            # Typed refusal: a value outside the exact profile vocabulary is never guessed or defaulted.
            logger.error(f"Compliance audit refused for '{product_id}': {ip}")
            agent.set_summary(f"Compliance audit refused: {ip}", status="FAILED")
            raise HTTPException(status_code=422, detail=ip.body())
        except ComplianceProfileRefused as pr:
            # Owner decisions 10-18 (CP-8 incomparable profiles, CP-10 unmapped Assured Workloads regime).
            logger.error(f"Compliance audit refused for '{product_id}': {pr}")
            agent.set_summary(f"Compliance audit refused: {pr}", status="FAILED")
            raise HTTPException(status_code=422, detail=pr.body())
        except PrivateIngressUnsupportedError as piu:
            # PRIVATE-INGRESS-EARLY-STOP: a typed refusal, not an outage. 409 -> the workflow's `except` -> the run ends
            # FAILED with this class, stage and message; vending and the developer never start.
            logger.error(f"Compliance stopped '{product_id}': {piu.reason}: {piu}")
            agent.set_summary(f"Compliance stopped the run: {piu.reason}: {piu}", status="FAILED")
            _write_compliance_stage_failed(trace_id, piu)
            raise
        except GateError as ge:
            # FD-4F / owner 19f: the handler's typed outage (remote compliance server unreachable / non-200 / empty)
            # keeps its reason (COMPLIANCE_UNAVAILABLE) -> 503 -> the workflow's existing `except` -> DLQ.
            logger.error(f"Compliance audit unavailable: {ge}")
            agent.set_summary(f"Compliance audit unavailable: {ge}", status="FAILED")
            if ge.stage == "compliance":
                _write_compliance_stage_failed(trace_id, ge)
            raise
        except Exception as e:
            # FD-4F (red-team F4): a compliance crash used to return PASSED + STANDARD + allow_unauthenticated=True
            # + requires_human_approval=False, turning a regulated/private workload into a public, HITL-free one.
            # It now fails closed: 503 GATE_UNAVAILABLE -> the workflow's existing `except` -> DLQ. A compliance
            # server OUTAGE is raised by the handler itself (above), not swallowed into the embedded engine.
            logger.error(f"Compliance audit failed: {e}", exc_info=True)
            agent.set_summary(f"Compliance audit unavailable: {type(e).__name__}: {e}", status="FAILED")
            raise GateUnavailableError(
                f"compliance audit unavailable: {type(e).__name__}: {e}",
                reason="COMPLIANCE_UNAVAILABLE",
                details={"product_id": product_id},
            ) from e


def _workload_vcs_kind(wdata: Dict[str, Any]) -> Optional[str]:
    """The workload's VCS provider: exact GITHUB / SERVERLESS_GIT (absent => GITHUB, the default everywhere), else None."""
    raw = wdata.get("vcs_provider")
    if raw is None or raw == "":
        return vcs_ledger.PROVIDER_GITHUB
    if isinstance(raw, str) and raw.strip().upper() in vcs_ledger.PROVIDERS:
        return raw.strip().upper()
    return None


def _recorded_base_branch(wdata: Any) -> str:
    """RT14-28: the workload's base branch from its record -- handler.workflow_branch(default_branch), the one rule of
    the developer's tree read and commit, QA's diff base, the IaC upgrade and the PR ledger check ("main" when none is
    recorded or the value is not a plain branch name, logged)."""
    from developer_agent.handler import workflow_branch

    recorded = wdata.get("default_branch") if isinstance(wdata, dict) else None
    return workflow_branch(recorded if isinstance(recorded, str) else None)


def _read_workload(gdb: Any, product_id: str) -> Optional[Dict[str, Any]]:
    snap = gdb.collection("workloads").document(product_id).get()
    return (snap.to_dict() or {}) if snap.exists else None


def _architect_vcs_kind(product_id: Optional[str]) -> Optional[str]:
    """PLAN-CONTRACT-CHECK (plan section 2.1): the workload's VCS kind for the architect's plan contract check, by
    `_workload_vcs_kind`'s rule on the recorded workload (absent value => GITHUB, invalid value => None). Every case
    where the record cannot be read maps to None, logged: no product id, no governance store, no record, or a read
    error. None never refuses or passes anything by itself: the check then does not evaluate its root
    `cloudbuild.yaml` clause and records that in the architect stage trace (`not_checked`), fail-loudly policy
    section 2 (the developer purge and the IMAGE_BUILD facet still apply later)."""
    if not isinstance(product_id, str) or not product_id:
        logger.warning("Architect plan contract: no product id, so the workload's VCS kind is unknown")
        return None
    gdb = get_governance_db()
    if gdb is None:
        logger.warning(f"Architect plan contract: no governance store, so the VCS kind of {product_id} is unknown")
        return None
    try:
        wdata = _read_workload(gdb, product_id)
    except Exception as e:  # noqa: BLE001 - an unreadable record is an unknown VCS kind (recorded), never a guess
        logger.warning(f"Architect plan contract: workload record {product_id} unreadable "
                       f"({type(e).__name__}: {e}), so its VCS kind is unknown")
        return None
    if not isinstance(wdata, dict):
        logger.warning(f"Architect plan contract: no workload record {product_id}, so its VCS kind is unknown")
        return None
    return _workload_vcs_kind(wdata)


def _pr_ledger_problems(vcs_kind: str, result: Dict[str, Any], branch: str) -> List[str]:
    """FD-4BB: refuse to record a PR whose live identity is not exactly the branch StackVend pushed in the workload
    repository (a fork head, another base repository, another head ref, another head commit)."""
    if result.get("branch_name") != branch:
        return [f"committed branch {result.get('branch_name')!r} is not {branch!r}"]
    return vcs_ledger.creation_problems(vcs_kind, repo_full_name=result.get("repo_name"), branch=branch,
                                        base_branch=result.get("base_branch"), commit_sha=result.get("commit_sha"),
                                        pull_request=result.get("pull_request"))


def _record_pr_ledger(trace_id: Optional[str], product_id: str, branch: str, result: Dict[str, Any],
                      origin: str) -> Optional[str]:
    """FD-4P: write the PR ledger entry for the branch/PR the developer step just created (identity from the
    provider's API response only). Returns the ledger id, or None when nothing was created that may ever be merged
    (no token / mock commit, PR creation failed, identity mismatch): the release step then refuses with
    RELEASE_FAILED/NO_LEDGER_ENTRY. A store failure is a typed 503 (fail loud: an unrecorded PR can never merge)."""
    if result.get("status") not in ("COMMITTED", "SUCCESS"):
        logger.warning(f"No PR ledger entry for {product_id} ({trace_id}): commit status {result.get('status')!r}")
        return None
    if db is None:
        # No store client at all (local / unconfigured gateway): nothing is recorded, so nothing can ever be merged;
        # the release step needs the same store and answers 503 GATE_UNAVAILABLE.
        logger.error(f"No PR ledger entry for {product_id} ({trace_id}): no Firestore client")
        return None
    try:
        wdata = _read_workload(db, product_id) or {}
    except Exception as e:
        raise GateUnavailableError(f"PR ledger: workload unreadable ({type(e).__name__})", reason="LEDGER_UNAVAILABLE",
                                   stage="developer") from e
    vcs_kind = _workload_vcs_kind(wdata)
    if vcs_kind is None:
        logger.error(f"No PR ledger entry for {product_id}: unknown vcs_provider {wdata.get('vcs_provider')!r}")
        return None
    problems = _pr_ledger_problems(vcs_kind, result, branch)
    expected_base = _recorded_base_branch(wdata)
    if result.get("base_branch") != expected_base:   # RT14-28: never a PR against another base than the record's
        problems = list(problems) + [f"commit base branch {result.get('base_branch')!r} is not the workload's "
                                     f"recorded base branch {expected_base!r}"]
    if problems:
        logger.error(f"No PR ledger entry for {product_id} ({trace_id}): {problems}",
                     extra={"security_event": "pr_identity_mismatch"})
        return None
    pr = result.get("pull_request") if vcs_kind == vcs_ledger.PROVIDER_GITHUB else None
    try:
        lid = vcs_ledger.record_created(
            db, provider=vcs_kind, repo_full_name=result.get("repo_name"),
            repo_id=pr.get("base_repo_id") if pr else None, product_id=product_id, trace_id=trace_id, origin=origin,
            branch=branch, base_branch=result.get("base_branch"), head_sha=result.get("commit_sha"),
            pr_number=pr.get("pr_number") if pr else None, pr_url=pr.get("pull_request_url") if pr else None)
    except vcs_ledger.LedgerMismatch as e:
        logger.error(f"No PR ledger entry for {product_id} ({trace_id}): {e}")
        return None
    except vcs_ledger.LedgerError as e:
        raise GateUnavailableError(f"PR ledger write failed: {e}", reason="LEDGER_UNAVAILABLE", stage="developer") from e
    logger.info(f"PR ledger: {vcs_kind} {result.get('repo_name')} {branch} (PR #{pr.get('pr_number') if pr else '-'}) -> {lid}")
    return lid


def _reconcile_superseded_prs(product_id: str, trace_id: Optional[str], keep_branch: str) -> None:
    """FD-4P (owner row 23): reconcile REWRITTEN on the ledger. Closes only open DEVELOPER entries of exactly this
    product + repository (earlier runs and earlier attempts of this run, RT H5), each only while its live PR still
    matches the ledger identity. Human PRs, forks, other products and pre-ledger PRs are unreachable.
    STOP-KEEPS-EVIDENCE (owner 11-14, RT F2): called only after the developer's own commit landed, never on a stop
    (generation or commit time), so a stopped run keeps the tested branch and its PR; skipped once the stage
    answered (RT F1).
    Never fails the run (non-destructive outcome)."""
    try:
        if db is None:
            return
        wdata = _read_workload(db, product_id) or {}
        vcs_kind = _workload_vcs_kind(wdata)
        if vcs_kind != vcs_ledger.PROVIDER_GITHUB:
            return  # Serverless Git: no PR objects to close (lane 3 follow-up: SHA-guarded branch delete)
        token = developer_agent.fetch_github_token()
        if not token:
            return
        full_repo_name = developer_agent.get_full_repo_name(product_id)
        entries = vcs_ledger.supersedable(vcs_ledger.entries_for_product(db, product_id), provider=vcs_kind,
                                          repo_full_name=full_repo_name, keep_branch=keep_branch)
        if not entries:
            return
        from shared.vcs_provider import VCSProviderFactory
        vcs = VCSProviderFactory.get_provider(provider_name=vcs_kind, default_owner=developer_agent.github_owner,
                                              project_id=developer_agent.project_id, github_token=token,
                                              product_id=product_id, full_repo_name=full_repo_name)
        res = vcs.reconcile_automated_pull_requests(full_repo_name, superseded=[vcs_ledger.identity(e) for e in entries])
        by_branch = {e["branch"]: e for e in entries}
        for row in (res or {}).get("results", []):
            e = by_branch.get(row.get("branch"))
            if e is None:
                continue
            if row.get("outcome") == "SUPERSEDED":
                vcs_ledger.mark(db, e["ledger_id"], vcs_ledger.STATE_SUPERSEDED, reason=f"superseded by trace {trace_id}")
            elif row.get("outcome") == "DIVERGED":
                vcs_ledger.mark(db, e["ledger_id"], vcs_ledger.STATE_DIVERGED, reason=row.get("reason"))
        logger.info(f"PR ledger reconcile for '{product_id}': {res}")
    except Exception as err:  # noqa: BLE001 - reconcile never blocks generation
        logger.warning(f"PR ledger reconcile notice for '{product_id}' ({type(err).__name__}: {err}); proceeding.")


# STOP-KEEPS-EVIDENCE (owner 11-14): how the tested branch's ledger entry was found for a stop's evidence
EVIDENCE_PR_FOUND = "FOUND"
EVIDENCE_PR_NOT_IN_LEDGER = "NOT_IN_LEDGER"
EVIDENCE_PR_LEDGER_UNAVAILABLE = "LEDGER_UNAVAILABLE"


def _kept_evidence(product_id: str, qa_feedback: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    """STOP-KEEPS-EVIDENCE: the tested branch a stopped QA retry keeps, {branch, commit_sha, pull_request,
    pr_lookup} (plus `summary`, the evidence sentence, once attached to a stop: RT F3). None without matched QA feedback (a first build or an unmatched retry: no tested branch is named;
    the earlier PRs are kept too, unnamed). The PR is the PR ledger's DEVELOPER entry of exactly this product, branch
    and tested commit (no other match); `pull_request` None with `pr_lookup` saying why. Never raises."""
    if not isinstance(qa_feedback, Mapping):
        return None
    branch, sha = qa_feedback.get("branch_name"), qa_feedback.get("commit_sha")
    if not (isinstance(branch, str) and branch and isinstance(sha, str) and sha):
        return None
    pr, lookup = None, EVIDENCE_PR_NOT_IN_LEDGER
    try:
        entries = vcs_ledger.entries_for_product(db, product_id)
    except Exception as e:  # noqa: BLE001 - LedgerUnavailable or a store failure: the branch is still named
        logger.warning(f"Stop evidence for '{product_id}': PR ledger unreadable ({type(e).__name__}); naming the "
                       f"branch only")
        entries, lookup = [], EVIDENCE_PR_LEDGER_UNAVAILABLE
    for e in entries:
        if (e.get("origin") == vcs_ledger.ORIGIN_DEVELOPER and e.get("branch") == branch
                and e.get("head_sha") == sha):
            pr = {"number": e.get("pr_number"), "url": e.get("pr_url"), "ledger_state": e.get("state"),
                  "ledger_id": e.get("ledger_id")}
            lookup = EVIDENCE_PR_FOUND
            break
    return {"branch": branch, "commit_sha": sha, "pull_request": pr, "pr_lookup": lookup}


def _evidence_sentence(evidence: Mapping[str, Any]) -> str:
    pr = evidence.get("pull_request") or {}
    where = (f", pull request #{pr.get('number')} ({pr.get('url')}) left as it was" if pr.get("number") is not None
             else "")
    return (f"Evidence kept: the tested branch {evidence['branch']!r} at commit {evidence['commit_sha']}{where}; "
            f"StackVend did not close it or delete the branch (STOP-KEEPS-EVIDENCE).")


def _attach_kept_evidence(stop: GateError, product_id: str, qa_feedback: Optional[Mapping[str, Any]]) -> None:
    """STOP-KEEPS-EVIDENCE: a typed stop of a matched QA retry names the tested branch / PR it kept, in its details
    (`evidence`) and in its message (the workflow's failure record keeps the summary). The class, reason, stage and
    diagnostics are unchanged; nothing is attached twice. Never raises (the stop is the outcome)."""
    try:
        if "evidence" in stop.details:
            return
        evidence = _kept_evidence(product_id, qa_feedback)
        if evidence is None:
            return
        sentence = _evidence_sentence(evidence)
        # RT F3: the sentence travels with the evidence, so a deadline / abandon answer that replaces this stop
        # (stage_deadline._carry_evidence) names the kept branch the same way
        stop.details["evidence"] = {**evidence, "summary": sentence}
        stop.message = f"{stop.message} {sentence}"
        stop.args = (stop.message,)
        logger.error(f"Developer stop for '{product_id}' ({stop.error_class.value} {stop.reason}): {sentence}")
    except Exception as e:  # noqa: BLE001 - the typed stop is raised unchanged
        logger.warning(f"Stop evidence for '{product_id}' not attached ({type(e).__name__}: {e})")


def _log_kept_evidence(failure: BaseException, product_id: str, trace_id: Optional[str],
                       qa_feedback: Optional[Mapping[str, Any]]) -> None:
    """STOP-KEEPS-EVIDENCE: any other failure of the generation or commit call (a typed stage error, a model
    failure, a failed push) leaves the PRs as they were too; logged with the tested branch when there is one. Never raises."""
    try:
        evidence = _kept_evidence(product_id, qa_feedback)
        if evidence is not None:
            logger.error(f"Developer dispatch for '{product_id}' (trace {trace_id}) failed "
                         f"({type(failure).__name__}): {_evidence_sentence(evidence)}")
    except Exception as e:  # noqa: BLE001 - the failure is raised unchanged
        logger.warning(f"Stop evidence for '{product_id}' not logged ({type(e).__name__}: {e})")


def _developer_gha_workflow_deletions(agent: Any, trace_id: Optional[str]) -> List[str]:
    """GHA-DEPLOY-SWITCH: the deploy workflow paths the developer's assembly marked for deletion for this trace
    (DeveloperAgent._assemble_tree, switch off). [] when there are none, or the agent records no such list (only a
    list of strings counts; anything else is no deletion)."""
    run = getattr(agent, "stack_run", None)
    record = run(trace_id) if callable(run) else None
    paths = record.get("gha_workflow_deletions") if isinstance(record, dict) else None
    if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
        return []
    return list(paths)


def _developer_app_orphan_deletions(agent: Any, trace_id: Optional[str]) -> List[str]:
    """SAT-49 F4: the earlier build's unchanged orphan files the developer decided to delete for this trace
    (DeveloperAgent._decide_app_orphans, after the stack validated the tree). [] when there are none or the record is
    not a list of strings (anything else is no deletion)."""
    run = getattr(agent, "stack_run", None)
    record = run(trace_id) if callable(run) else None
    paths = record.get("app_orphan_deletions") if isinstance(record, dict) else None
    if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
        return []
    return list(paths)


def _record_topology_context(trace_id: Optional[str], product_id: str, files: Dict[str, Any],
                             result: Dict[str, Any]) -> None:
    """Lane 10 (FD-51): after the developer committed a topology run, keep its validated service topology on
    workloads/{product_id}.service_topology (status PR_OPENED) as CONTEXT for the next architect run on this product
    (FEATURE_REQUEST / regeneration: "keep every existing service"). Never an authority: the developer always
    re-validates the trace's own record against the repository (brownfield guard). Best-effort, logged."""
    if not (db and trace_id):
        return
    try:
        from shared.service_topology import TOPOLOGY_JSON_PATH, topology_from_record
        text = files.get(TOPOLOGY_JSON_PATH) if isinstance(files, dict) else None
        if not isinstance(text, str):
            return
        record = json.loads(text)
        vt, _ = topology_from_record(record, product_id=product_id, file=TOPOLOGY_JSON_PATH)
        if vt is None:
            logger.error(f"Committed topology.json for {product_id} ({trace_id}) does not re-validate; not recorded")
            return
        db.collection("workloads").document(product_id).set({"service_topology": {
            "record": record, "trace_id": trace_id, "status": "PR_OPENED",
            "branch": result.get("branch_name"), "commit_sha": result.get("commit_sha")}}, merge=True)
    except Exception as rec_err:  # noqa: BLE001 - context for the next architect run only
        logger.warning(f"Could not record the committed service topology for {product_id} ({trace_id}): {rec_err}")


def _assert_tf_remediation_allowed(req: DeveloperExecuteRequest, gdb: Any) -> None:
    """Lane 17 RT F6 (AJ-14): a terraform remediation dispatch is refused when tf-applier persisted a non-remediable
    error_class (STATE_LOCKED, DEPLOY_TIMEOUT, ...) for this trace: those need an operator, and an LLM rewrite of the
    IaC cannot fix them (it only burns the remediation budget). Exact set membership on the persisted class. An empty
    class stays remediable during the lane 6 transition (Q9). Store unreadable -> 503 (no blind re-run)."""
    if not (req.tf_remediation_context or "").strip() or not req.trace_id:
        return
    if gdb is None:
        raise GateUnavailableError("terraform remediation guard: pipeline store unavailable", reason="STORE_UNAVAILABLE",
                                   stage="developer")
    try:
        snap = gdb.collection("pipeline_executions").document(req.trace_id).get()
        data = (snap.to_dict() or {}) if snap.exists else {}
    except Exception as e:
        raise GateUnavailableError(f"terraform remediation guard: pipeline store unreadable ({type(e).__name__})",
                                   reason="STORE_UNAVAILABLE", stage="developer") from e
    tf_stage = ((data.get("stages") or {}).get("terraform") or {}) if isinstance(data.get("stages"), dict) else {}
    cls = tf_stage.get("error_class") if isinstance(tf_stage, dict) else None
    # WF-OPERATOR-FLAG (owner 10-27): same meaning as the workflow's check_deploy_status: a persisted
    # `operator_required` that is exactly the boolean True also refuses remediation, whatever the class.
    flagged = isinstance(tf_stage, dict) and tf_stage.get("operator_required") is True
    if (isinstance(cls, str) and cls in NON_REMEDIABLE_DEPLOY_CLASSES) or flagged:
        shown = cls if isinstance(cls, str) and cls else "operator_required"
        raise OperatorActionRequiredError(
            f"terraform failed with {shown}: operator action required; developer remediation refused",
            reason=shown, stage="developer", details={"lock_holder": tf_stage.get("lock_holder")})
    if (req.tf_retry_count or 0) >= 1:
        _assert_developer_owns_deploy_failure(req, tf_stage if isinstance(tf_stage, dict) else {})


def _assert_developer_owns_deploy_failure(req: DeveloperExecuteRequest, tf_stage: Dict[str, Any]) -> None:
    """DEPLOY-FAILURE-OWNER-ROUTER (owner 11-13): the automatic terraform remediation loop (the workflow increments
    tf_retry_count before every dispatch) is an ALLOW-list. The developer is dispatched only when the terraform server's
    recorded route (`stages.terraform.failure_route`) names DEVELOPER as owner AND describes exactly this failure: its
    `error_sha256` equals sha256 of the dispatch's tf_remediation_context (the deploy result's error the workflow
    forwards). Anything else is a typed refusal with class, stage, owner and the failing files: PLATFORM_DEFECT ->
    PlatformDefectError (503); every other owner, no route, or a route of another failure ->
    OperatorActionRequiredError (409). An operator's RESUME_DEVELOPER relaunch (tf_retry_count 0) is not checked."""
    route = tf_stage.get(DEPLOY_FAILURE_ROUTE_FIELD)
    route = route if isinstance(route, dict) else None
    context = req.tf_remediation_context or ""
    digest = hashlib.sha256(context.encode("utf-8")).hexdigest()
    owner = route.get("owner") if route is not None else None
    paired = route is not None and route.get("error_sha256") == digest
    if owner == DEPLOY_OWNER_DEVELOPER and paired:
        return
    findings = [{k: f.get(k) for k in ("owner", "reason", "file", "line", "address")}
                for f in ((route or {}).get("findings") or [])[:5] if isinstance(f, dict)]
    details = {"owner": owner if isinstance(owner, str) else None,
               "phase": (route or {}).get("phase"), "basis": (route or {}).get("basis"),
               "failure_class": (route or {}).get("error_class"), "findings": findings}
    if route is None:
        reason = NO_DEPLOY_FAILURE_ROUTE
    elif not paired:
        reason = DEPLOY_FAILURE_ROUTE_STALE
    else:
        reason = owner if isinstance(owner, str) and owner in DEPLOY_OWNERS else NO_DEPLOY_FAILURE_ROUTE
    where = (f" ({findings[0].get('address') or ''} {findings[0].get('file') or ''}".rstrip() + ")") if findings else ""
    message = (f"terraform failure not owned by the developer: {reason}{where}; developer remediation refused "
               f"(DEPLOY-FAILURE-OWNER-ROUTER)")
    logger.error(message)
    if paired and owner == DEPLOY_OWNER_PLATFORM_DEFECT:
        raise PlatformDefectError(message, reason=reason, stage="developer", details=details)
    raise OperatorActionRequiredError(message, reason=reason, stage="developer", details=details)


def _compliance_decision_unavailable(message: str, *, product_id: str, failure: str,
                                     **details: Any) -> GateUnavailableError:
    return GateUnavailableError(
        f"compliance decision unavailable for the developer ({message}); the run stops instead of guessing ingress",
        reason="COMPLIANCE_DECISION_UNAVAILABLE", stage="developer",
        details={"product_id": product_id, "failure": failure, **details})


def _resolve_developer_compliance_decision(req: DeveloperExecuteRequest, gdb: Any) -> Dict[str, Any]:
    """FD-4R R-6: the persisted compliance decision (workloads/{product}/compliance_audits/{trace}) is the ONLY source
    of the developer's ingress flags; the request's legacy flags are ignored. Lookup, by exact document id:
    1. `compliance_trace_id` when sent (the workflow sends the prior FULL trace on RESUME_DEVELOPER): that record or
       nothing;
    2. else this run's `trace_id` (a FULL run: the compliance stage of the same trace wrote it);
    3. else the trace of `workloads/{product}.last_prebuild_gate` (an older workflow's RESUME_DEVELOPER: the record
       `/agent/resume/outcome` already validated).
    No store, a read error, no record or an incomplete/mismatched record -> GATE_UNAVAILABLE
    `COMPLIANCE_DECISION_UNAVAILABLE` (503): never a default, never a spec-keyword guess."""
    pid = req.product_id
    if gdb is None:
        raise _compliance_decision_unavailable("no Firestore client", product_id=pid, failure="NO_STORE")
    try:
        workload_ref = gdb.collection("workloads").document(pid)

        def _read(trace: str) -> Optional[Dict[str, Any]]:
            snap = workload_ref.collection("compliance_audits").document(trace).get()
            return (snap.to_dict() or {}) if snap.exists else None

        if req.compliance_trace_id:
            source, lookup = req.compliance_trace_id, "compliance_trace_id"
            record = _read(source)
        else:
            source, lookup, record = None, None, None
            if req.trace_id:
                source, lookup = req.trace_id, "trace_id"
                record = _read(source)
            if record is None:
                w_snap = workload_ref.get()
                gate = ((w_snap.to_dict() or {}) if w_snap.exists else {}).get("last_prebuild_gate")
                gate_trace = gate.get("trace_id") if isinstance(gate, dict) else None
                if isinstance(gate_trace, str) and gate_trace and gate_trace != req.trace_id:
                    source, lookup = gate_trace, "last_prebuild_gate"
                    record = _read(source)
    except GateError:
        raise
    except Exception as e:
        raise _compliance_decision_unavailable(f"store unreadable: {type(e).__name__}", product_id=pid,
                                               failure="READ") from e
    if record is None or not source:
        raise _compliance_decision_unavailable("no persisted compliance decision", product_id=pid,
                                               failure="NOT_FOUND", trace_id=req.trace_id,
                                               compliance_trace_id=req.compliance_trace_id)
    problems = _wf_gates.developer_decision_problems(record, product_id=pid, trace_id=source)
    if problems:
        raise _compliance_decision_unavailable("persisted compliance decision is incomplete or mismatched",
                                               product_id=pid, failure="INVALID", source_trace_id=source,
                                               problems=problems)
    logger.info(f"Developer ingress for '{pid}' from the persisted compliance decision of trace {source} "
                f"(via {lookup}): allow_unauthenticated={record['allow_unauthenticated']} "
                f"enable_direct_iap={record['enable_direct_iap']} "
                f"domain_restricted_sharing={record['domain_restricted_sharing']}")
    return {"source_trace_id": source, "lookup": lookup,
            "allow_unauthenticated": record["allow_unauthenticated"],
            "enable_direct_iap": record["enable_direct_iap"],
            "domain_restricted_sharing": record["domain_restricted_sharing"],
            "allowed_domains": list(record["allowed_domains"]),
            # Lane 14 PR-0b on R-6 (Fable RT F3): the regulated render comes from this same record. Passed as stored
            # (None when a pre-R-6 v1 record lacks a field); the developer validates them against the profile.
            "compliance_profile": record.get("compliance_profile"),
            "is_regulated": record.get("is_regulated"),
            "requires_cmek": record.get("requires_cmek"),
            "requires_audit_logging": record.get("requires_audit_logging"),
            # ADHERENCE-PLATFORM-SATISFIED: the stage's typed plan-time access warnings, as stored (QA validates them)
            "access_advisories": record.get("access_advisories")}


# QA-REPAIR-OWNERSHIP-PARITY (SAT-49): the exact paths the developer wrote in a committed build, per trace, on
# pipeline_executions/{trace}.stages.developer.committed_draft = {commit_sha, llm_draft_paths} (overwritten per commit;
# the trace id is constant across the workflow's dispatches). A repair dispatch treats exactly those files as its
# draft, and only when the record's commit is exactly the commit the repair starts from.
COMMITTED_DRAFT_FIELD = "committed_draft"
COMMITTED_DRAFT_NOT_RECORDED = "COMMITTED_DRAFT_NOT_RECORDED"


def _record_committed_draft(agent: Any, trace_id: Optional[str], result: Dict[str, Any]) -> None:
    """SAT-49 (Fable RT F3/F6): after commit_and_open_pr returned COMMITTED (or SUCCESS: the PyGithub fallback path,
    the same rule as _record_pr_ledger) with a commit sha, record the commit and the loop's final
    LLM draft set of this dispatch (DeveloperAgent.stack_run(trace)["llm_draft_paths"]). Never fails the commit: a
    record that cannot be made (no store, no draft set, more than DRAFT_PATHS_MAX paths, a write failure) is an ERROR
    log with code COMMITTED_DRAFT_NOT_RECORDED, and the next repair of this commit regenerates
    (DRAFT_PATHS_UNAVAILABLE: its commit matches no record)."""
    if result.get("status") not in ("COMMITTED", "SUCCESS") or not is_commit_sha(result.get("commit_sha")) \
            or not trace_id:
        return
    sha = result["commit_sha"]

    def not_recorded(reason: str) -> None:
        logger.error(f"{COMMITTED_DRAFT_NOT_RECORDED}: trace {trace_id}, commit {sha}: {reason}; a repair of this "
                     f"commit regenerates (DRAFT_PATHS_UNAVAILABLE)")

    if db is None:
        return not_recorded("NO_STORE")
    run = getattr(agent, "stack_run", None)
    record = run(trace_id) if callable(run) else None
    paths = record.get("llm_draft_paths") if isinstance(record, dict) else None
    if isinstance(paths, list) and len(paths) > _DRAFT_PATHS_MAX:
        return not_recorded(f"TOO_MANY_PATHS ({len(paths)} > {_DRAFT_PATHS_MAX})")
    if _draft_paths_of(paths) is None:
        return not_recorded("NO_DRAFT_PATHS")
    try:
        db.collection("pipeline_executions").document(trace_id).set({"stages": {"developer": {COMMITTED_DRAFT_FIELD: {
            "commit_sha": sha, "llm_draft_paths": sorted(paths), **_committed_draft_extras(record, result)}}}},
            merge=True)
    except Exception as e:  # noqa: BLE001 - mirrors _write_iac_provenance: never fails the commit
        return not_recorded(f"WRITE_FAILED ({type(e).__name__})")
    logger.info(f"Committed draft of trace {trace_id} recorded: commit {sha}, {len(paths)} path(s)")


def _read_committed_draft(gdb: Any, trace_id: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """(the trace's committed_draft record, "") or (None, why not). Never raises."""
    try:
        snap = gdb.collection("pipeline_executions").document(trace_id).get()
        data = (snap.to_dict() or {}) if snap.exists else {}
    except Exception as e:  # noqa: BLE001 - an unreadable record is no record
        return None, f"READ_FAILED ({type(e).__name__})"
    stages = data.get("stages") if isinstance(data, dict) else None
    dev = stages.get("developer") if isinstance(stages, dict) else None
    rec = dev.get(COMMITTED_DRAFT_FIELD) if isinstance(dev, dict) else None
    if not isinstance(rec, dict):
        return None, "NO_RECORD"
    if _draft_paths_of(rec.get("llm_draft_paths")) is None:
        return None, "RECORD_INVALID"
    return rec, ""


def _matched_draft_paths(gdb: Any, trace_id: str, sha: str) -> Tuple[Optional[List[str]], str]:
    """The recorded draft paths when the record's commit is exactly `sha` (exact string equality), else (None, why)."""
    rec, why = _read_committed_draft(gdb, trace_id)
    if rec is None:
        return None, why
    if rec.get("commit_sha") != sha:
        return None, f"COMMIT_MISMATCH (record {rec.get('commit_sha')!r}, expected {sha})"
    return sorted(rec["llm_draft_paths"]), ""


def _committed_draft_extras(record: Any, result: Mapping[str, Any]) -> Dict[str, Any]:
    """QA-REPAIR-KEEPS-ORPHAN-DELETIONS (PROVENANCE-HISTORY note): beside the draft paths, the commit's orphan
    deletions (the developer's decided deletions that this commit really deleted, exact paths) and its committed paths
    (what the platform wrote in it). Both keys are always written (Firestore merges leaf by leaf: a missing key would
    keep an earlier commit's value). A list over _DRAFT_PATHS_MAX is not recorded ([] / None)."""
    orphans = record.get("app_orphan_deletions") if isinstance(record, dict) else None
    deleted = result.get("files_deleted")
    kept = sorted({p for p in (orphans or []) if isinstance(p, str) and isinstance(deleted, list) and p in deleted})
    committed = result.get("files_committed")
    committed_ok = (isinstance(committed, list) and all(isinstance(p, str) for p in committed)
                    and len(committed) <= _DRAFT_PATHS_MAX)
    base_sha = result.get("base_head_sha")
    return {_QA_ORPHAN_DELETIONS_FIELD: kept if len(kept) <= _DRAFT_PATHS_MAX else [],
            _QA_COMMITTED_PATHS_FIELD: sorted(committed) if committed_ok else None,
            # RT14-13: the base head the commit's base check saw (None when it was not checked)
            _QA_BASE_HEAD_SHA_FIELD: base_sha if is_commit_sha(base_sha) else None}


def _matched_commit_extras(gdb: Any, trace_id: str, sha: str) -> Dict[str, Any]:
    """QA-REPAIR-KEEPS-ORPHAN-DELETIONS: the orphan deletions and committed paths of the record of exactly commit
    `sha` (the commit QA tested), for the QA repair dispatch. Anything else (no record, another commit, a value that
    is not a list of strings) -> omitted: the repair carries nothing forward (today's behaviour)."""
    rec, _why = _read_committed_draft(gdb, trace_id)
    if rec is None or rec.get("commit_sha") != sha:
        return {}
    out: Dict[str, Any] = {}
    for key in (_QA_ORPHAN_DELETIONS_FIELD, _QA_COMMITTED_PATHS_FIELD):
        value = rec.get(key)
        if isinstance(value, list) and all(isinstance(p, str) for p in value) and len(value) <= _DRAFT_PATHS_MAX:
            out[key] = sorted(value)
    if is_commit_sha(rec.get(_QA_BASE_HEAD_SHA_FIELD)):   # RT14-13: the base the tested commit was cut from
        out[_QA_BASE_HEAD_SHA_FIELD] = rec[_QA_BASE_HEAD_SHA_FIELD]
    return out


# TI-5-R3-d (owner 10-25, FOLLOWUPS-1025): the field the Control Center's RESUME_DEVELOPER relaunch writes on the new
# execution's record (apps/control-center/routes/workloads.py RESUME_TF_VALIDATION_REPORT_FIELD): the failed deploy's
# typed report and the trace whose release that deploy applied.
RESUME_TF_VALIDATION_REPORT_FIELD = "resume_tf_validation_report"
RESUME_EXECUTION_MODE = "RESUME_DEVELOPER"


def _resume_validation_report(req: DeveloperExecuteRequest) -> Optional[Tuple[Dict[str, Any], str]]:
    """TI-5-R3-d: on the FIRST developer dispatch of a resumed run (no report in the request, tf_retry_count and
    retry_count 0; the workflow YAML is unchanged), (the failed deploy's validation_report, its source trace) from
    `pipeline_executions/{trace}.resume_tf_validation_report`, used only when the record is this product's
    RESUME_DEVELOPER execution and the field holds a dict report and a source trace other than this one. Any other
    case -> None: the dispatch is today's path (a record that is present but unusable is logged). Never raises."""
    if req.tf_validation_report is not None or (req.tf_retry_count or 0) != 0 or (req.retry_count or 0) != 0:
        return None
    if not req.trace_id:
        return None
    gdb = get_evidence_db()
    if gdb is None:
        return None
    try:
        snap = gdb.collection("pipeline_executions").document(req.trace_id).get()
        data = (snap.to_dict() or {}) if snap.exists else {}
    except Exception as e:  # noqa: BLE001 - an unreadable record is no record
        logger.warning(f"Resume validation report not read for '{req.product_id}' (trace {req.trace_id}): "
                       f"READ_FAILED ({type(e).__name__}); regenerating without it")
        return None
    rec = data.get(RESUME_TF_VALIDATION_REPORT_FIELD) if isinstance(data, dict) else None
    if rec is None:
        return None

    def skip(reason: str) -> None:
        logger.warning(f"Resume validation report not used for '{req.product_id}' (trace {req.trace_id}): {reason}; "
                       f"regenerating without it")
        return None

    if data.get("execution_mode") != RESUME_EXECUTION_MODE:
        return skip("NOT_A_RESUME_EXECUTION")
    if data.get("product_id") != req.product_id:
        return skip("PRODUCT_MISMATCH")
    report = rec.get("validation_report") if isinstance(rec, dict) else None
    source = rec.get("source_trace_id") if isinstance(rec, dict) else None
    if not isinstance(report, dict):
        return skip("RECORD_INVALID")
    if not isinstance(source, str) or not source or source == req.trace_id:
        return skip("SOURCE_TRACE_INVALID")
    logger.info(f"Resume of '{req.product_id}' (trace {req.trace_id}) forwards the failed deploy's validation report "
                f"of trace {source}")
    return report, source


def _deploy_repair_draft_paths(req: DeveloperExecuteRequest,
                               release_trace_id: Optional[str] = None) -> Optional[List[str]]:
    """SAT-49 (Fable RT F2): on a terraform remediation dispatch with a typed report, the draft paths of the build the
    deploy applied: the trace's committed_draft, used only when its commit is exactly the head commit of this trace's
    most recently created MERGED developer PR ledger entry (the release this deploy came from). Anything else -> None
    (logged): an INTENT_REPAIR then regenerates (DRAFT_PATHS_UNAVAILABLE); every other plan is unchanged.
    TI-5-R3-d: on a resumed run the deploy applied the SOURCE trace's release (`release_trace_id`, from the forwarded
    record), so the same exact checks run on that trace."""
    if req.tf_validation_report is None or not req.trace_id:
        return None
    trace = release_trace_id or req.trace_id

    def skip(reason: str) -> None:
        logger.warning(f"Deploy repair draft not used for '{req.product_id}' (trace {trace}): {reason}")
        return None

    gdb = get_evidence_db()
    if gdb is None:
        return skip("NO_STORE")
    try:
        entries = vcs_ledger.entries_for_product(gdb, req.product_id)
    except Exception as e:  # noqa: BLE001 - LedgerUnavailable or a store failure: no match
        return skip(f"LEDGER_UNAVAILABLE ({type(e).__name__})")
    merged = [e for e in entries if e.get("trace_id") == trace and e.get("origin") == vcs_ledger.ORIGIN_DEVELOPER
              and e.get("state") == vcs_ledger.STATE_MERGED and is_commit_sha(e.get("head_sha"))]
    if not merged:
        return skip("NO_MERGED_DEVELOPER_PR")
    released = max(merged, key=lambda e: str(e.get("created_at") or ""))
    paths, why = _matched_draft_paths(gdb, trace, released["head_sha"])
    if paths is None:
        return skip(why)
    return paths


def _qa_repair_feedback(req: DeveloperExecuteRequest) -> Optional[Dict[str, Any]]:
    """QA-FEEDBACK (register row QA-FEEDBACK, owner 10-27; workflow YAML unchanged): on a QA retry dispatch
    (retry_count > 0; only `increment_qa_retry` raises it) the QA evidence of this trace, `qa_test_runs/{trace_id}`
    (run_qa: full overwrite per attempt), plus the tree QA tested, fetched AT the recorded commit. Returned only when
    every check holds: same trace and product, passed False, error_class CODE_DEFECT, retryable, attempt ==
    retry_count - 1, and the tested branch's head is still the recorded commit (the commit the repair starts from).
    Any mismatch or failure -> None (logged): the developer regenerates exactly as before (nothing else changes).
    The first build (retry_count 0) reads nothing."""
    retry = req.retry_count or 0
    if retry <= 0:
        return None

    def skip(reason: str) -> None:
        logger.warning(f"QA feedback not used for '{req.product_id}' (trace {req.trace_id}, retry {retry}): {reason}; "
                       f"regenerating without it")
        return None

    if not req.trace_id:
        return skip("NO_TRACE")
    if req.tf_validation_report is not None:
        # a terraform remediation dispatch (TI-5-R3's own path); `increment_qa_retry` nulls the report, while a
        # stale tf_remediation_context from an earlier deploy round stays on a QA retry (the record decides)
        return skip("TF_REMEDIATION_DISPATCH")
    evidence_db = get_evidence_db()
    if evidence_db is None:
        return skip("NO_EVIDENCE_STORE")
    try:
        snap = evidence_db.collection("qa_test_runs").document(req.trace_id).get()
        data = snap.to_dict() if snap.exists else None
    except Exception as e:  # noqa: BLE001 - an unreadable record is no record
        return skip(f"READ_FAILED ({type(e).__name__})")
    if not isinstance(data, dict):
        return skip("NO_RECORD")
    if data.get("trace_id") != req.trace_id:
        return skip("TRACE_MISMATCH")
    if data.get("product_id") != req.product_id:
        return skip("PRODUCT_MISMATCH")
    if data.get("passed") is not False:
        return skip("NOT_FAILED")
    if data.get("error_class") != ErrorClass.CODE_DEFECT.value:
        return skip("NOT_CODE_DEFECT")
    if data.get("retryable") is not True:
        return skip("NOT_RETRYABLE")
    attempt = data.get("attempt")
    if type(attempt) is not int or attempt != retry - 1:
        return skip(f"ATTEMPT_MISMATCH (record {attempt!r}, expected {retry - 1})")
    sha, branch = data.get("commit_sha"), data.get("branch_name")
    if not is_commit_sha(sha) or not isinstance(branch, str) or not branch:
        return skip("COMMIT_UNKNOWN")
    try:
        validate_relpath(branch)
    except (UnsafePathError, ValueError):
        return skip("BRANCH_INVALID")
    diagnostics = data.get("diagnostics")
    if not isinstance(diagnostics, list) or not diagnostics:
        return skip("NO_DIAGNOSTICS")
    try:
        tree = fetch_tree_at_head(get_source_backend_factory()(req.product_id), branch, sha)
    except BranchMovedError as e:
        return skip(f"COMMIT_MISMATCH (head of {branch} is {e.actual_sha}, QA tested {sha})")
    except Exception as e:  # noqa: BLE001 - BranchFetchError or a backend failure: no tree, no repair
        return skip(f"FETCH_FAILED ({type(e).__name__})")
    if tree.commit_sha != sha:
        return skip(f"COMMIT_MISMATCH (archive {tree.commit_sha}, QA tested {sha})")
    logger.info(f"QA feedback for '{req.product_id}' (trace {req.trace_id}): attempt {attempt}, commit {sha}, "
                f"{len(diagnostics)} diagnostic(s)")
    # QA-STAGE2-ONLY-REPAIR: the record's typed reason (run_qa: STAGE2_FAILED = tests passed, the judges blocked)
    reason = data.get("reason")
    # SAT-49: the exact files the developer wrote in the tested build (record of exactly this commit); without them
    # the developer regenerates (DRAFT_PATHS_UNAVAILABLE)
    draft_paths, why = _matched_draft_paths(evidence_db, req.trace_id, sha)
    if draft_paths is None:
        logger.warning(f"QA feedback for '{req.product_id}' (trace {req.trace_id}) has no draft record of commit "
                       f"{sha}: {why}; the developer regenerates (DRAFT_PATHS_UNAVAILABLE)")
    return {"trace_id": req.trace_id, "attempt": attempt, "commit_sha": sha, "branch_name": branch,
            "diagnostics": [dict(d) for d in diagnostics if isinstance(d, dict)], "files": dict(tree.files_text),
            _QA_REASON_FIELD: reason if isinstance(reason, str) else None,
            **({_QA_DRAFT_PATHS_FIELD: draft_paths} if draft_paths is not None else {}),
            **(_matched_commit_extras(evidence_db, req.trace_id, sha) if draft_paths is not None else {})}


def _execute_developer_logic(req: DeveloperExecuteRequest) -> Dict[str, Any]:
    import uuid
    _assert_tf_remediation_allowed(req, get_governance_db())
    branch_suffix = uuid.uuid4().hex[:6]

    # Zero-LLM Deterministic Branch for IaC Upgrades
    if req.change_type == "IAC_UPGRADE":
        from shared.vcs_provider import VCSProviderFactory
        from shared.iac_upgrade_engine import (ModuleDeletionScopeError, module_files_removed_by_upgrade,
                                               upgrade_workload_iac_vendoring)
        branch_name = f"iac-upgrade/{req.product_id}-{branch_suffix}"
        provider = VCSProviderFactory.get_provider(product_id=req.product_id)
        repo_identifier = None  # FD-4P (RT F12): only workloads/{product_id}.github_repo, never the request
        # IAC-UPGRADE-DEFAULT-BRANCH: the tree is read from the branch commit_and_open_pr cuts the upgrade branch
        # from and opens the PR against -- workloads/{product_id}.default_branch (FD-4CI-b-R1), "main" when none is
        # recorded (the same rule as commit_and_open_pr). Was always "main": a workload on another branch was
        # upgraded from the wrong base.
        # RT14-28: the developer's rule (handler.workflow_branch of the record; was the raw value, so a value that is
        # not a plain branch name was read here and committed against "main"); unreadable -> typed, never "main"
        base_branch = "main"
        if db:
            try:
                w_doc = db.collection("workloads").document(req.product_id).get()
            except Exception as e:
                raise GateUnavailableError(f"workloads/{req.product_id} unreadable ({type(e).__name__})",
                                           reason="WORKLOAD_RECORD_UNREADABLE", stage="developer") from e
            if w_doc.exists:
                w_data = w_doc.to_dict() or {}
                repo_identifier = w_data.get("github_repo")
                base_branch = _recorded_base_branch(w_data)

        # FD-4DC: the whole tree or IncompleteRepoTreeError (REPO_TREE_INCOMPLETE); never an upgrade of a partial tree
        existing_files = provider.fetch_file_tree(repo_identifier or req.product_id, branch=base_branch,
                                                  require_complete=True)
        updated_files, upgraded_mods, _ = upgrade_workload_iac_vendoring(
            files=existing_files,
            modules_to_upgrade=req.modules_to_upgrade,
            author=req.author or "Operator",
            firestore_client=db,
        )
        commit_msg = f"chore(iac): upgrade vendored modules ({', '.join(upgraded_mods)}) to latest"
        # FD-4DC-d/e: the gate checks the whole tree after the upgrade (`updated_files` = the read tree with the
        # upgraded module files replaced and the dropped ones removed); only the module files the upgrade changed or
        # added are written, and the module .tf files the new version dropped are deleted (upgraded modules only).
        if not upgraded_mods:   # nothing to write: no branch, no commit, no PR (the CC Upgrade IaC answer)
            return {"status": "SUCCESS", "product_id": req.product_id, "branch_name": "", "tasks_executed": 0,
                    "files_count": 0, "pull_request_url": "",
                    "summary": "All vendored modules are already up to date; nothing was committed."}
        changed = [p for p, c in updated_files.items() if existing_files.get(p) != c]
        try:
            dropped = module_files_removed_by_upgrade(existing_files, updated_files, upgraded_mods)
        except ModuleDeletionScopeError as e:
            raise PlatformDefectError(f"{e.error_class}: {e}. Nothing was committed and no pull request was opened.",
                                      reason=e.error_class, stage="developer") from e
        result = developer_agent.commit_and_open_pr(
            product_id=req.product_id,
            files=updated_files,
            branch_name=branch_name,
            commit_message=commit_msg,
            github_repo=repo_identifier,
            trace_id=req.trace_id,
            commit_paths=changed,
            files_to_delete=dropped,
        )
        if result.get("status") == "FAILED":
            raise RuntimeError(f"IaC upgrade commit failed: {result.get('error')}")
        _record_pr_ledger(req.trace_id, req.product_id, branch_name, result, vcs_ledger.ORIGIN_IAC_UPGRADE)
        return {
            "status": "SUCCESS",
            "product_id": req.product_id,
            "branch_name": branch_name,
            "tasks_executed": 1,
            "files_count": len(changed),        # FD-4DC-d: the files written (was the whole tree)
            "files_deleted": dropped,
            "pull_request_url": result.get("pull_request_url", ""),
            "summary": f"Deterministic IaC upgrade upgraded {len(upgraded_mods)} modules on branch {branch_name}.",
        }

    branch_name = f"castor/{req.product_id}-{branch_suffix}"
    spec_text = req.spec_text or f"Workload service implementation for {req.product_id}"
    # FD-4R R-6: ingress comes from the persisted compliance decision only, resolved before any VCS or LLM call.
    decision = _resolve_developer_compliance_decision(req, get_governance_db())
    # RESUME-DEVELOPER-TASK-DAG: a long-specification resume builds the plan QA will judge it against (None: unchanged)
    kept_task_dag = _resume_developer_task_dag(req, spec_text, get_governance_db())
    if kept_task_dag is not None:
        req = req.model_copy(update={"task_dag": kept_task_dag})
    # TI-5-R3-d: a resumed run's first dispatch plans with the failed deploy's report the Control Center forwarded
    resumed = _resume_validation_report(req)
    if resumed is not None:
        req = req.model_copy(update={"tf_validation_report": resumed[0]})
    # QA-FEEDBACK: the tested branch's tree and evidence; None = today's regeneration
    qa_feedback = _qa_repair_feedback(req)
    # SAT-49: a terraform remediation dispatch's draft = the released build's own files (None = not matched)
    deploy_draft_paths = _deploy_repair_draft_paths(req, release_trace_id=resumed[1] if resumed is not None else None)

    # 1. Generate full source code files (FastAPI, Firestore, Terraform, Dockerfile, tests)
    # STOP-KEEPS-EVIDENCE (owner 11-14): the QA repair plan is decided inside generate_code_files. A typed stop there
    # (PLATFORM_DEFECT, OPERATOR_ACTION_REQUIRED, any typed failure) leaves BEFORE the PR reconcile, which runs only
    # after this dispatch's own commit landed (below), so the tested branch and its PR stay as the run's evidence,
    # and the stop names them (_attach_kept_evidence).
    try:
        files = developer_agent.generate_code_files(
            product_id=req.product_id,
            spec_text=spec_text,
            task_dag=req.task_dag or [],
            trace_id=req.trace_id,
            plan_markdown=req.plan_markdown,
            plan_file_path=req.plan_file_path,
            domain_restricted_sharing=decision["domain_restricted_sharing"],
            allowed_domains=decision["allowed_domains"],
            allow_unauthenticated=decision["allow_unauthenticated"],
            enable_direct_iap=decision["enable_direct_iap"],
            target_compute_services=req.target_compute_services or [],
            architect_compute_intent=req.architect_compute_intent,
            access=req.access,
            tf_retry_count=req.tf_retry_count or 0,
            tf_remediation_context=req.tf_remediation_context,
            tf_validation_report=req.tf_validation_report,   # TI-5-R3
            # Lane 14 PR-0b on R-6: the regulated controls come from the same resolved record (no second read).
            compliance_decision={k: decision[k] for k in ("source_trace_id", "compliance_profile", "is_regulated",
                                                          "requires_cmek", "requires_audit_logging")},
            **({"qa_feedback": qa_feedback} if qa_feedback is not None else {}),   # QA-FEEDBACK: matched retry only
            **({_DEPLOY_DRAFT_PATHS_KWARG: deploy_draft_paths} if deploy_draft_paths is not None else {}),   # SAT-49
        )
    except GateError as stop:
        _attach_kept_evidence(stop, req.product_id, qa_feedback)
        raise
    except Exception as failure:
        _log_kept_evidence(failure, req.product_id, req.trace_id, qa_feedback)
        raise

    # GHA-DEPLOY-SWITCH: a GitHub workload whose switch is off gets no deploy workflow; the workflow files an earlier
    # run committed (.github/workflows/deploy-*.yml of the tree the developer read) are deleted in this commit and
    # listed in the answer. On (every workload before the switch): nothing to delete, the call is unchanged.
    gha_deletions = _developer_gha_workflow_deletions(developer_agent, req.trace_id)
    if gha_deletions:
        logger.info(f"GHA_DEPLOY_WORKFLOWS_DELETED: {req.product_id}: GitHub Actions deploy is off; deleting "
                    f"{gha_deletions}")
    # SAT-49 F4: an earlier build's files this build no longer writes, unchanged since the platform wrote them and not
    # used by any file that stays, are deleted in the same commit (none: the call is unchanged)
    orphan_deletions = [p for p in _developer_app_orphan_deletions(developer_agent, req.trace_id)
                        if p not in gha_deletions]
    if orphan_deletions:
        logger.info(f"APP_ORPHANS_DELETED: {req.product_id}: deleting {orphan_deletions}")

    # 2. Commit and push files to GitHub repository
    # STOP-KEEPS-EVIDENCE RT F2: a commit-time stop (PRECOMMIT_VERIFY_FAILED, PLATFORM.COMMIT_TREE_MISMATCH, the
    # RT14-13 base-moved stop, VCS_CREDENTIAL_UNAVAILABLE, the developer.commit orphan guard, a clone / push failure)
    # comes before the reconcile too, so it keeps the tested branch and PR and names them like a generation stop.
    try:
        result = developer_agent.commit_and_open_pr(
            product_id=req.product_id,
            files=files,
            branch_name=branch_name,
            commit_message=f"feat({req.product_id}): automated implementation by StackVend Developer Agent",
            trace_id=req.trace_id,
            **({"files_to_delete": gha_deletions + orphan_deletions} if gha_deletions or orphan_deletions else {}),
        )
        if result.get("status") == "FAILED":
            raise RuntimeError(f"Developer Agent GitHub commit failed: {result.get('error')}")
    except GateError as stop:
        _attach_kept_evidence(stop, req.product_id, qa_feedback)
        raise
    except Exception as failure:
        _log_kept_evidence(failure, req.product_id, req.trace_id, qa_feedback)
        raise
    _record_committed_draft(developer_agent, req.trace_id, result)   # SAT-49: the next repair's draft (never raises)
    _record_pr_ledger(req.trace_id, req.product_id, branch_name, result, vcs_ledger.ORIGIN_DEVELOPER)
    # FD-4P: supersede earlier StackVend PRs of this product (ledger entries only; human PRs are unreachable).
    # STOP-KEEPS-EVIDENCE RT F2: only once this dispatch's own commit landed; an entry a stopped dispatch kept is
    # superseded by the next dispatch that commits. RT F1: the reconcile closes PRs and deletes branches, so it never
    # runs once the stage answered (deadline, run ended, superseded, emergency stop). It is skipped with a log line,
    # never raised: the commit has landed, and a landed commit must not turn into a failed stage.
    answered = stage_deadline.answered()
    if answered is not None:
        logger.warning(f"PR ledger reconcile skipped for '{req.product_id}' (trace {req.trace_id}): the developer "
                       f"stage answered ({answered[0]}) after the commit on {branch_name!r} landed; earlier StackVend "
                       f"PRs stay open until the next dispatch that commits (STOP-KEEPS-EVIDENCE).")
    else:
        _reconcile_superseded_prs(req.product_id, req.trace_id, keep_branch=branch_name)
    _record_topology_context(req.trace_id, req.product_id, files, result)

    # SLOW-CALL-FALLBACK: which model wrote what (a run may mix models after a timeout or transient fallback)
    model_provenance = (developer_agent.stack_run(req.trace_id) or {}).get("model_provenance")
    model_provenance = model_provenance if isinstance(model_provenance, dict) else {}
    who = model_provenance.get("summary")
    written_by = f" {who[:1].upper()}{who[1:]}." if isinstance(who, str) and who else ""
    return {
        "status": "SUCCESS",
        "product_id": req.product_id,
        "branch_name": branch_name,
        "tasks_executed": len(req.task_dag),
        "files_count": len(files),
        "pull_request_url": result.get("pull_request_url", ""),
        # FD-4F / owner 19b: the exact paths this run committed (post pre-commit cure) and the commit, so the
        # workflow can scope the gatekeeper's GK-5 check (`committed_paths`) to this run's files. Additive fields.
        "commit_sha": result.get("commit_sha"),
        "files_committed": result.get("files_committed"),
        # FD-4R R-6: which persisted compliance decision set this run's ingress (additive field).
        "compliance_trace_id": decision["source_trace_id"],
        "summary": f"Developer implemented {len(files)} files on branch {branch_name}.{written_by}",
        # SLOW-CALL-FALLBACK: {summary, mixed, outputs[{output, model, primary_model, fallback, fallback_reason}]}
        **({"model_provenance": model_provenance} if model_provenance.get("outputs") else {}),
        # GHA-DEPLOY-SWITCH: the deploy workflow files this commit deleted (additive; present only when any were).
        **({"files_deleted": gha_deletions + orphan_deletions} if gha_deletions or orphan_deletions else {}),
        # SAT-49 F4: the earlier build's orphan files among them (additive; present only when any were)
        **({"app_orphans_deleted": orphan_deletions} if orphan_deletions else {}),
    }


def _typed_failure_fields(err: "StageError", limit: int = 50) -> Dict[str, Any]:
    """error_class + bounded diagnostics of a StageError (shared.diagnostics), for the callback outcome."""
    report = err.report
    diags = [d.model_dump(mode="json") for d in (report.diagnostics or [])]
    return {
        "error_class": report.error_class.value if report.error_class else None,
        "validation_status": report.status,
        "tools_unavailable": list(report.tools_unavailable or []),
        "exhausted_reason": getattr(err, "exhausted_reason", None),
        "diagnostics": diags[:limit],
        "diagnostics_total": len(diags),
    }


def _sync_stage_error_response(err: "StageError", product_id: str) -> Optional[JSONResponse]:
    """TI-5-R3-c (owner 10-25, FOLLOWUPS-1025): the synchronous /agent/developer/execute answers a typed developer
    StageError with its class and HTTP status (shared.diagnostics.HTTP_STATUS; a RepairBudgetExhausted is 409) and
    the same typed fields as the async callback (_typed_failure_fields), so the workflow's failure handler records
    the real class instead of DEPENDENCY_FAILED. None (a report without a class) keeps the untyped 500."""
    fields = _typed_failure_fields(err)
    cls = err.report.error_class
    if cls is None or not fields.get("error_class"):
        return None
    budget = isinstance(err, RepairBudgetExhausted)
    code = 409 if budget else HTTP_STATUS.get(cls, 500)
    body = {"status": "FAILED", "passed": False, "stage": "developer", "product_id": product_id,
            "summary": str(err), "errors": [str(err)],
            **({"reason": "REPAIR_BUDGET_EXHAUSTED"} if budget else {}), **fields}
    logger.error(f"Developer typed failure for '{product_id}': {fields['error_class']} (HTTP {code}): {err}")
    return JSONResponse(status_code=code, content=body)


def run_developer_execute_in_background(req: DeveloperExecuteRequest):
    trace_id = req.trace_id or f"dev-async-{req.product_id}"
    with AgentLifecycle("Developer", req.product_id, trace_id, mode="ASYNC CALLBACK", extra_metadata={"Attempt": (req.retry_count or 0) + 1}) as agent:
        with guaranteed_callback_scope(
            callback_url=req.callback_url,
            trace_id=trace_id,
            stage_name="developer",
            product_id=req.product_id,
            firestore_db=db,
        ) as outcome:
            logger.info(f"Starting async developer execution for product '{req.product_id}' (trace: {trace_id})")
            try:
                res = _execute_developer_logic(req)
            except GateError as ge:
                # FD-4F (red-team F5): keep the typed gate outcome in the callback body (error_class + diagnostics).
                outcome.update(ge.to_body(product_id=req.product_id))
                outcome["error"] = ge.message
                agent.set_summary(f"Developer gate failure ({ge.error_class.value}): {ge.message}", status="FAILED")
                return
            except StageError as stage_err:
                # Step 1 code RT F4: a typed developer failure carries its class and diagnostics in the callback
                # (extra keys; the scope still records status FAILED and error "<Type>: <msg>" exactly as before).
                outcome.update(_typed_failure_fields(stage_err))
                raise
            except DeveloperStageError as dev_err:
                # Lane 14 PR-0b RT F2: lane 19 / PR-0b typed refusals (LLM_UNAVAILABLE, COMPLIANCE_REGION_NOT_ALLOWED,
                # ...) keep their class in the callback body (additive key; status / error string unchanged).
                outcome["error_class"] = dev_err.error_class
                if isinstance(dev_err, (LlmFallbackExhausted, LlmStageBudgetExhausted)):
                    outcome.update(dev_err.to_body())   # SLOW-CALL-FALLBACK RT F11: reason, stage, every attempt
                raise
            outcome["status"] = res.get("status", "SUCCESS")
            outcome["product_id"] = req.product_id
            outcome["branch_name"] = res.get("branch_name")
            outcome["pull_request_url"] = res.get("pull_request_url")
            outcome["files_count"] = res.get("files_count", 0)
            outcome["tasks_executed"] = res.get("tasks_executed", 0)
            outcome["summary"] = res.get("summary")
            outcome["outputs"] = res
            agent.set_summary(res.get("summary", "Developer execution completed"), status=outcome["status"])


@app.post("/agent/developer/execute-async", status_code=status.HTTP_202_ACCEPTED)
def developer_execute_async(req: DeveloperExecuteRequest, background_tasks: BackgroundTasks):
    """
    Asynchronously executes Developer Agent code generation and opens a PR.
    Returns HTTP 202 Accepted immediately to prevent orchestrator HTTP timeouts.
    Notifies Cloud Workflows via callback upon completion.
    """
    background_tasks.add_task(run_developer_execute_in_background, req)
    return {
        "status": "ACCEPTED",
        "product_id": req.product_id,
        "trace_id": req.trace_id,
        "message": "Developer execution dispatched to background worker. Workflow will resume via callback.",
    }


@app.post("/agent/developer/execute")
def developer_execute(req: DeveloperExecuteRequest):
    """Step 4 (synchronous form): the developer under its SYNC stage deadline (STAGE-DEADLINE)."""
    return _run_stage("developer", StageMode.SYNC, req.trace_id, req.product_id, lambda: _developer_execute_body(req))


@app.post("/agent/developer/execute-job", status_code=status.HTTP_202_ACCEPTED)
def developer_execute_job(req: DeveloperExecuteJobRequest):
    """Step 4 (LONG-STAGE-CALLBACK): 202 once the stage-runner execution exists; the answer arrives on
    `callback_url`."""
    return _submit_stage_job("developer", req)


def _developer_execute_body(req: DeveloperExecuteRequest):
    """
    Invoked by Step 4 of castor_main_orchestrator workflow.
    Executes Developer Agent logic to generate application code, commit to GitHub, and open a PR.
    """
    with AgentLifecycle("Developer", req.product_id, req.trace_id or "auto-trace", mode="SYNC", extra_metadata={"Attempt": (req.retry_count or 0) + 1}) as agent:
        try:
            res = _execute_developer_logic(req)
            agent.set_summary(res.get("summary", ""), status="SUCCESS")
            return res
        except GateError as ge:
            # FD-4F (red-team F5): typed gate failures keep their error_class (503/422 via _gate_error_handler)
            # instead of collapsing into an untyped HTTP 500.
            agent.set_summary(f"Developer gate failure ({ge.error_class.value}): {ge.message}", status="FAILED")
            raise
        except StageError as se:
            typed = _sync_stage_error_response(se, req.product_id)   # TI-5-R3-c
            if typed is None:
                agent.set_summary(f"Developer execution failed: {str(se)}", status="FAILED")
                logger.error(f"Developer execution failed: {se}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(se))
            agent.set_summary(f"Developer typed failure (HTTP {typed.status_code}): {se}", status="FAILED")
            return typed
        except (LlmFallbackExhausted, LlmStageBudgetExhausted) as e:
            # SLOW-CALL-FALLBACK: a typed body (class, reason, stage, every model attempt), so the workflow's
            # build_failure records the real class without a YAML change. 503: no model answered in time; 504: the
            # stage budget left no room for a call.
            code = 504 if isinstance(e, LlmStageBudgetExhausted) else 503
            agent.set_summary(f"Developer typed failure (HTTP {code}): {e}", status="FAILED")
            logger.error(f"Developer typed failure for '{req.product_id}': {e.error_class} (HTTP {code}): {e}")
            return JSONResponse(status_code=code, content={
                "status": "FAILED", "passed": False, "product_id": req.product_id, "summary": str(e),
                "errors": [str(e)], **e.to_body()})
        except IncompleteRepoTreeError as e:   # FD-4DC RT F2: typed refusal (IAC_UPGRADE on a partial tree)
            agent.set_summary(f"Developer refused ({e.error_class}): {e}", status="FAILED")
            logger.error(f"Developer execution refused: {e.error_class}: {e}")
            raise HTTPException(status_code=409, detail=f"{e.error_class}: {e}. Nothing was committed and no pull "
                                                        f"request was opened.")
        except Exception as e:
            agent.set_summary(f"Developer execution failed: {str(e)}", status="FAILED")
            logger.error(f"Developer execution failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))


@app.post("/agent/gatekeeper/verify")
def gatekeeper_verify(req: GatekeeperVerifyRequest, source_backend_factory: Any = Depends(get_source_backend_factory)):
    """Step 4.5: the gatekeeper under its SYNC stage deadline (STAGE-DEADLINE)."""
    return _run_stage("gatekeeper", StageMode.SYNC, req.trace_id, req.product_id,
                      lambda: _gatekeeper_verify_body(req, source_backend_factory))


def _gatekeeper_verify_body(req: GatekeeperVerifyRequest, source_backend_factory: Any):
    """
    Invoked by Step 4.5 of castor_main_orchestrator workflow.
    Verifies the COMMITTED tree of the feature branch (in-memory AST import validation, requirements reconciliation,
    container contracts, compilation) before code enters QA or Release Promotion.

    FD-4F (GK-1/2/4/5, D7): fail closed. A fetch error or an empty tree is GATE_UNAVAILABLE (never "skipped"); the
    tree is fetched as ONE archive at ONE resolved commit SHA (returned as `commit_sha` for QA/release); the
    verdict is on the committed bytes, and if the verifier's own cure would change them the committed tree is not
    what the pre-commit gate validated -> PLATFORM_DEFECT.
    """
    from gatekeeper_agent.verifier import SynthesisVerifierAgent  # GK-4: hard import, no fallback

    trace_id = req.trace_id
    with AgentLifecycle("Gatekeeper", req.product_id, trace_id, mode="SYNC") as agent:
        if (req.files is None) == (req.branch_name is None):
            raise HTTPException(status_code=422, detail="exactly one of `files` or `branch_name` is required")

        commit_sha: Optional[str] = None
        if req.branch_name is not None:
            try:
                tree = fetch_tree_at_head(source_backend_factory(req.product_id), req.branch_name)
            except BranchFetchError as e:
                agent.set_summary(f"Gatekeeper unavailable: {e}", status="FAILED")
                raise GateUnavailableError(
                    f"gatekeeper could not fetch the committed tree of '{req.branch_name}': {e}", reason="SOURCE_FETCH"
                ) from e
            files = tree.files_text
            commit_sha = tree.commit_sha
        else:
            files = dict(req.files or {})

        if not files:
            agent.set_summary("Gatekeeper unavailable: zero files to verify", status="FAILED")
            raise GateUnavailableError("gatekeeper received an empty file tree", reason="EMPTY_TREE")

        try:
            gatekeeper = SynthesisVerifierAgent(product_id=req.product_id)
            # FD-55 W5 (F4): a typed-intent tree (intent + its render, exact paths) skips the same IaC cure the
            # generation-time pass skipped, so the three verify_and_cure callers agree by construction
            from developer_agent.iac_intent_contract import is_intent_tree
            typed_iac_tree = is_intent_tree(files)
            cured, passed, errors = gatekeeper.verify_and_cure(
                dict(files), product_id=req.product_id,
                typed_iac=typed_iac_tree
            )
        except Exception as e:
            agent.set_summary(f"Gatekeeper verifier crashed: {e}", status="FAILED")
            raise GateUnavailableError(f"gatekeeper verifier crashed: {type(e).__name__}: {e}", reason="VERIFIER_ERROR") from e

        # GK-5: exact comparison, no heuristic. The pre-commit gate (commit_and_open_pr) cured exactly the files this
        # run committed, so re-curing THOSE committed bytes must be a no-op. Owner condition 19b: only this run's
        # files are judged, by exact path (`committed_paths`), with the same input the pre-commit cure had; files
        # that pre-exist in the repo (brownfield, untouched services from earlier runs) are not part of the check.
        if req.committed_paths is not None:
            gk5_scope = "committed_paths"
            scope_paths = sorted(set(req.committed_paths))
            missing = [p for p in scope_paths if p not in files]
            if missing:
                agent.set_summary(f"Gatekeeper: {len(missing)} committed paths are missing from the branch", status="FAILED")
                raise PlatformDefectError(
                    f"{len(missing)} path(s) the developer reported as committed are not text files in the committed "
                    f"tree of '{req.branch_name}' at {commit_sha}",
                    reason="COMMITTED_PATH_MISSING",
                    details={"missing_paths": missing[:100], "commit_sha": commit_sha},
                )
            gk5_input = {p: files[p] for p in scope_paths}
            try:
                gk5_cured, _, _ = gatekeeper.verify_and_cure(
                    dict(gk5_input), product_id=req.product_id,
                    typed_iac=typed_iac_tree   # FD-55 W5 (F4): decided on the whole committed tree, not the subset
                )
            except Exception as e:
                agent.set_summary(f"Gatekeeper verifier crashed: {e}", status="FAILED")
                raise GateUnavailableError(f"gatekeeper verifier crashed: {type(e).__name__}: {e}", reason="VERIFIER_ERROR") from e
        else:
            gk5_scope = "whole_tree"
            gk5_input, gk5_cured = files, cured
        changed = sorted(k for k in set(gk5_input) | set(gk5_cured) if gk5_input.get(k) != gk5_cured.get(k))
        if changed:
            agent.set_summary(f"Gatekeeper: cure would change {len(changed)} committed files", status="FAILED")
            scope_text = (
                "files this run committed" if gk5_scope == "committed_paths"
                else "files in the committed tree (no committed_paths sent, so pre-existing files are included)"
            )
            raise PlatformDefectError(
                f"the gatekeeper's own cure would change {len(changed)} of the {scope_text}: the committed bytes are "
                f"not what the pre-commit cure produced (non-idempotent cure, or the verifier changed between commit "
                f"and this gate). An LLM retry cannot fix this; operator action is required. See "
                f"details.changed_paths.",
                reason="CURE_WOULD_CHANGE_TREE",
                details={"changed_paths": changed[:100], "commit_sha": commit_sha, "gk5_scope": gk5_scope},
            )

        status_str = "SUCCESS" if passed else "FAILED"
        summary_msg = "AST and container contracts 100% verified" if passed else f"Detected {len(errors)} compilation/contract issues"
        agent.set_summary(summary_msg, status=status_str)
        return {
            "status": status_str,
            "passed": bool(passed),
            "error_class": None if passed else ErrorClass.CODE_DEFECT.value,
            "product_id": req.product_id,
            "branch_name": req.branch_name,
            "commit_sha": commit_sha,
            "gk5_scope": gk5_scope,
            "summary": summary_msg,
            "cured_files_count": 0,
            "errors": errors,
            "diagnostics": [
                {"tool": "gatekeeper", "code": "GATEKEEPER.CONTRACT", "severity": "error", "file": None, "line": None, "message": str(e)}
                for e in errors
            ],
        }


def record_qa_sign_off_on_plan(
    db_client: Any,
    product_id: str,
    branch_name: str,
    passed: bool,
    summary: str,
    trace_id: Optional[str] = None,
    error_class: Optional[str] = None,
):
    """Appends the QA sign-off section to the implementation plan in Firestore.

    FD-4F (red-team F8): uses the injected client (no raw firestore.Client) and distinguishes a gate that could not
    run (BLOCKED) from code that failed QA (FAILED). This is a side record, not a gate: failures are logged at ERROR.
    """
    if db_client is None:
        logger.error(f"QA sign-off for '{product_id}' not recorded: no Firestore client")
        return
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        if passed:
            plan_status, label = "VERIFIED", "✅ PASSED"
        elif error_class in (ErrorClass.GATE_UNAVAILABLE.value, ErrorClass.PLATFORM_DEFECT.value):
            plan_status, label = "BLOCKED", f"⛔ BLOCKED ({error_class})"
        else:
            plan_status, label = "FAILED", "❌ FAILED"

        plans_ref = db_client.collection("workloads").document(product_id).collection("implementation_plans")
        docs = list(plans_ref.order_by("created_at", direction="DESCENDING").limit(1).stream())
        if not docs:
            docs = list(db_client.collection("implementation_plans").where("product_id", "==", product_id).limit(1).stream())

        for doc in docs:
            data = doc.to_dict() or {}
            existing_md = data.get("markdown", "")
            qa_signoff = (
                f"\n\n## 8. Verification & QA Sign-Off\n"
                f"- **Status**: {label}\n"
                f"- **Branch**: `{branch_name}`\n"
                f"- **Sign-Off Timestamp**: `{now_iso}`\n"
                f"- **Verification Summary**: {summary}\n"
                f"- **Verified By**: StackVend Autonomous QA Reviewer Agent\n"
            )
            updated_md = existing_md if "## 8. Verification & QA Sign-Off" in existing_md else (existing_md + qa_signoff)
            update_data = {
                "status": plan_status,
                "qa_passed": passed,
                "qa_error_class": error_class,
                "qa_summary": summary,
                "qa_verified_at": now_iso,
                "markdown": updated_md,
            }
            doc.reference.set(update_data, merge=True)
            db_client.collection("implementation_plans").document(f"{product_id}_{doc.id}").set(update_data, merge=True)
            logger.info(f"Recorded QA sign-off ({plan_status}) on implementation plan '{doc.id}' for workload '{product_id}'")
    except Exception as err:
        logger.error(f"Could not record QA sign-off on implementation plan: {err}")


def _qa_access_unavailable(message: str, **details: Any) -> GateUnavailableError:
    return GateUnavailableError(f"Stage 2 access policy unavailable ({message}); QA stops instead of guessing ingress",
                                reason="QA_ACCESS_POLICY", details=details)


def _qa_ingress_policy(product_id: str, trace_id: str, wdata: Dict[str, Any], db_client: Any,
                       compliance_trace_id: Optional[str] = None) -> Dict[str, Any]:
    """The security judge's ingress policy (`_qa_access`, first element)."""
    return _qa_access(product_id, trace_id, wdata, db_client, compliance_trace_id=compliance_trace_id)[0]


def _qa_access(product_id: str, trace_id: str, wdata: Dict[str, Any], db_client: Any,
               compliance_trace_id: Optional[str] = None) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """QA-STAGE2-POLICY (owner 10-27): the security judge's ingress policy, resolved exactly like the developer's
    (developer_agent.handler._resolve_run_access): the record `workloads/{pid}.access` plus the persisted compliance
    decision of this trace (FD-4R R-6 lookup, `_resolve_developer_compliance_decision`), through
    `access_resolution.resolve_access` (most restrictive wins). The former top-level `allow_unauthenticated /
    enable_direct_iap / requires_vpc` fields were never written by anything, so every judge was told "private, no
    IAP" whatever the workload was. Fail closed (GATE_UNAVAILABLE `QA_ACCESS_POLICY`): no / unreadable compliance
    decision, an invalid or incomplete access record, a conflict, or an unapproved widening."""
    if wdata.get(_wf_gates.ACCESS_WIDENING_APPROVAL_FIELD) is not None:
        raise _qa_access_unavailable("the access record was widened and the widening is not approved yet",
                                     product_id=product_id, failure="ACCESS_WIDENING_UNAPPROVED")
    # QA-INGRESS-RESUME-TRACE: a resume is judged on the decision of the gate it reused, never on a newer run's.
    lookup = SimpleNamespace(product_id=product_id, trace_id=trace_id, compliance_trace_id=compliance_trace_id)
    try:
        decision = _resolve_developer_compliance_decision(lookup, db_client)
    except GateError as ge:
        raise _qa_access_unavailable(ge.message, product_id=product_id, failure=ge.reason or "COMPLIANCE_DECISION",
                                     **{k: v for k, v in ge.details.items() if k not in ("product_id", "failure")}) from ge
    from developer_agent.access_resolution import resolve_access
    from developer_agent.errors import DeveloperStageError

    try:
        resolved = resolve_access(workload_access=wdata.get("access"),
                                  allow_unauthenticated=decision["allow_unauthenticated"],
                                  enable_direct_iap=decision["enable_direct_iap"],
                                  domain_restricted_sharing=decision["domain_restricted_sharing"] is True)
    except DeveloperStageError as e:
        raise _qa_access_unavailable(str(e), product_id=product_id, failure=e.error_class) from e
    logger.info(f"QA Stage 2 access policy for '{product_id}' (trace {trace_id}): mode={resolved.mode} "
                f"source={resolved.source} invokers={len(resolved.invoker_members)}")
    # ADHERENCE-PLATFORM-SATISFIED: the same decision's typed plan-time access advisories, checked exactly as the
    # pre-build gate checks them (a malformed list is a contract break: fail closed, never dropped).
    try:
        advisories = _wf_gates.access_advisories_of({"access_advisories": decision.get("access_advisories")})
    except ValueError as ve:
        raise _qa_access_unavailable(str(ve), product_id=product_id, failure="ACCESS_ADVISORIES_INVALID") from ve
    return {
        "access_mode": resolved.mode,
        "access_source": resolved.source,
        "allow_unauthenticated": resolved.allow_unauthenticated,
        "enable_direct_iap": resolved.enable_direct_iap,
        "invoker_principal_count": len(resolved.invoker_members),
    }, advisories


def _resume_gate_trace(execution: Dict[str, Any]) -> Optional[str]:
    """The trace of the passed gate this RESUME_DEVELOPER run reused, as `/agent/resume/outcome` recorded it on the run;
    None on any other run."""
    gate = execution.get(_wf_gates.RESUME_GATE_FIELD)
    gate_trace = gate.get("trace_id") if isinstance(gate, dict) else None
    if (not isinstance(gate_trace, str) or not gate_trace
            or gate.get("status") not in _wf_gates.RESUMABLE_GATE_STATUSES):
        return None
    return gate_trace


def _resume_gate_task_dag(product_id: str, execution: Dict[str, Any], db_client: Any) -> List[Dict[str, Any]]:
    """RESUME-DEVELOPER-TASK-DAG: the Task DAG kept for the gate decision this RESUME_DEVELOPER run reused, as
    `/agent/resume/outcome` recorded it on the run (never the workload's current gate, which a newer run can replace);
    [] when none is usable (the caller raises QA_CONTEXT). The store unreadable is GATE_UNAVAILABLE, like the other
    context reads."""
    gate = execution.get(_wf_gates.RESUME_GATE_FIELD)
    gate_trace = _resume_gate_trace(execution)
    if not gate_trace:
        return []
    try:
        snap = (db_client.collection("workloads").document(product_id)
                .collection(_wf_gates.TASK_DAG_COLLECTION).document(gate_trace).get())
    except Exception as e:
        raise GateUnavailableError(f"Stage 2 context read failed: {type(e).__name__}: {e}", reason="QA_CONTEXT") from e
    record = (snap.to_dict() or {}) if snap.exists else None
    task_dag, problem = _wf_gates.persisted_task_dag(record, product_id=product_id, prebuild_gate=gate)
    if problem:
        logger.warning(f"Task DAG of gate trace {gate_trace} not usable for QA of {product_id}: {problem}")
    return task_dag


def _resume_developer_task_dag(req: DeveloperExecuteRequest, spec_text: str,
                               db_client: Any) -> Optional[List[Dict[str, Any]]]:
    """RESUME-DEVELOPER-TASK-DAG (owner 11-09, review F4 option A): the Task DAG a RESUME_DEVELOPER dispatch builds from
    when its specification rules out the solo fast path, so the swarm sees the plan QA's adherence judge checks. It is
    the judge's own record (`_resume_gate_task_dag`), read here because the workflow's resume carries no DAG.

    None = the dispatch keeps what it was sent. No store read happens unless the request has the shape only a resume
    has: no DAG, and a compliance trace other than its own (a full build's is its own trace). A short specification
    keeps the empty DAG, which is what selects the single-pass repair. A store error stops the run with a typed 503
    before any developer spend; no usable kept DAG leads to the stop QA already makes (`QA_CONTEXT`), never a made-up DAG."""
    if req.task_dag or not req.trace_id or not req.compliance_trace_id or req.compliance_trace_id == req.trace_id:
        return None
    if not spec_rules_out_solo_fast_path(spec_text):
        return None
    try:
        snap = db_client.collection("pipeline_executions").document(req.trace_id).get()
        execution = (snap.to_dict() or {}) if snap.exists else {}
        if execution.get("execution_mode") != RESUME_EXECUTION_MODE or execution.get("product_id") != req.product_id:
            return None
        task_dag = _resume_gate_task_dag(req.product_id, execution, db_client)
    except Exception as e:  # the store, directly or through the judge's reader: never taken for "no plan was kept"
        raise GateUnavailableError(
            f"the kept Task DAG of this resume could not be read ({type(e).__name__}); the run stops before developer spend",
            reason="RESUME_TASK_DAG_UNREADABLE", stage="developer",
            details={"product_id": req.product_id, "trace_id": req.trace_id}) from e
    if not task_dag:
        logger.warning(f"Resume of '{req.product_id}' (trace {req.trace_id}) has no usable kept Task DAG; the developer "
                       f"runs without one and QA stops the run (QA_CONTEXT)")
        return None
    logger.info(f"Resume of '{req.product_id}' (trace {req.trace_id}) builds from the kept Task DAG ({len(task_dag)} tasks)")
    return task_dag


def _fetch_pipeline_context_for_qa(
    product_id: str, trace_id: str, db_client: Any, request_task_dag: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Stage 2 judge context. FD-4F (red-team F9): a missing store, workload or pipeline record is
    GATE_UNAVAILABLE. The judges must never run against a fabricated empty DAG or default ingress policy."""
    if db_client is None:
        raise GateUnavailableError("Stage 2 context unavailable: no Firestore client", reason="QA_CONTEXT")
    try:
        w_doc = db_client.collection("workloads").document(product_id).get()
        pe_doc = db_client.collection("pipeline_executions").document(trace_id).get()
    except Exception as e:
        raise GateUnavailableError(f"Stage 2 context read failed: {type(e).__name__}: {e}", reason="QA_CONTEXT") from e
    if not w_doc.exists:
        raise GateUnavailableError(f"Stage 2 context unavailable: workloads/{product_id} not found", reason="QA_CONTEXT")
    if not pe_doc.exists:
        raise GateUnavailableError(f"Stage 2 context unavailable: pipeline_executions/{trace_id} not found", reason="QA_CONTEXT")

    wdata = w_doc.to_dict() or {}
    pdata = pe_doc.to_dict() or {}
    ingress_policy, access_advisories = _qa_access(product_id, trace_id, wdata, db_client,
                                                   compliance_trace_id=_resume_gate_trace(pdata))
    stages = pdata.get("stages", {})
    arch_st = stages.get("architect", {})
    arch_details = arch_st.get("details", {})
    task_dag = arch_details.get("task_dag") or arch_st.get("task_dag") or []
    if not task_dag:
        task_dag = (arch_details.get("infra_tasks") or []) + (arch_details.get("code_tasks") or [])
    if not task_dag and request_task_dag:
        task_dag = list(request_task_dag)
    if not task_dag and pdata.get("execution_mode") == RESUME_EXECUTION_MODE:
        # RESUME-DEVELOPER-TASK-DAG: a resume has no architect stage and the workflow has no DAG to send it; the plan
        # it is judged against is the one the pre-build gate it reused decided on.
        task_dag = _resume_gate_task_dag(product_id, pdata, db_client)
    if not task_dag:
        # F9 / RT C7: an adherence verdict against an empty DAG is fabricated (nothing can be "missed").
        raise GateUnavailableError(
            f"Stage 2 context unavailable: no Task DAG for trace {trace_id} (not persisted, not sent with the request)",
            reason="QA_CONTEXT",
        )
    comp_st = stages.get("compliance", {})
    return {
        "task_dag": task_dag,
        "ingress_policy": ingress_policy,
        "compliance_frameworks": comp_st.get("details", {}).get("active_frameworks") or ["SOC2-BASELINE"],
        "compliance_summary": comp_st.get("summary") or "",
        "workload_policy": wdata,
        "access_advisories": access_advisories,   # ADHERENCE-PLATFORM-SATISFIED (typed, validated)
        # TEST-LAYOUT-PLATFORM-FACT: the service list the developer built this trace with (ComputeIntent.service_names,
        # recorded by the developer); None when absent or not a list of strings (no layout fact: fail closed).
        "service_names": _developer_service_names(pdata),
    }


def _developer_service_names(pdata: Dict[str, Any]) -> Optional[List[str]]:
    """`pipeline_executions/{trace}.developer_compute_intent.service_names` exactly as the developer recorded it (the
    typed input of developer_agent.workload_test_layout), or None when it is absent or not a list of strings."""
    rec = pdata.get("developer_compute_intent")
    names = rec.get("service_names") if isinstance(rec, dict) else None
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        return None
    return list(names)


# ------------------------------------------------------------------------------
# FD-4F: QA verification core (one implementation for the sync and the async route)
# ------------------------------------------------------------------------------
# STAGE-DEADLINE: the QA SYNC row of stage_deadline.STAGE_BUDGETS (1500 s, unchanged). run_qa reads the current stage
# deadline (SYNC: this value; CALLBACK: the longer callback budget) and falls back to this for a direct call.
QA_REQUEST_DEADLINE_S = stage_deadline.budget_for("qa", StageMode.SYNC).budget_s
# QA-JUDGE-RETRY (owner 10-27): Stage 2 gets min(STAGE_TWO_DEADLINE_S = 300 s, remaining - STAGE_TWO_MARGIN_S). The
# margin keeps the evidence write and the response inside QA_REQUEST_DEADLINE_S; Stage 2 starts only when 120 s
# (JUDGE_TIMEOUT_S) are left after the margin (else GATE_UNAVAILABLE DEADLINE, as before). JUDGE-FALLBACK-FLASH-ROOM
# (owner 11-16): within Stage 2 each judge call is time-boxed (qa_auditor.judge.attempt_timeout_s, 55..120 s) so a later
# fallback model keeps room; 120 s holds two 55 s boxes plus the judge's 5 s margin.
STAGE_TWO_MARGIN_S = 30
STAGE_TWO_MIN_REMAINING_S = int(_qa_judge.JUDGE_TIMEOUT_S) + STAGE_TWO_MARGIN_S


def _platform_golden_copies(head_files: Dict[str, str]) -> frozenset:
    """QA-STAGE2-INPUT (owner 10-27): the committed files that are the platform's own golden-module copies, by the
    exact vendoring source: `terraform_engine.get_canonical_module_files()` (what `vendor_terraform_modules` copies
    into `infra/modules/`) plus, for each `infra/bundles/<id>/` directory of the tree that is a built-in bundle,
    exactly what `vendor_composite_bundle` writes. A file counts only when its path AND its content are identical to
    that source (no path or text guessing): a copy the AI changed, a custom module or an unknown bundle is shown to
    the judges like any other file. The developer's per-run record (`vendor_platform_files`) is not persisted, so
    this recomputes it from the same source; an unreadable catalog stops Stage 2 (GATE_UNAVAILABLE QA_CONTEXT)."""
    try:
        from developer_agent.terraform_engine import get_canonical_module_files, vendor_composite_bundle
        from shared.builtin_bundles_payload import get_builtin_bundle

        source: Dict[str, str] = dict(get_canonical_module_files())
        bundle_ids = sorted({p.split("/")[2] for p in head_files
                             if p.split("/")[:2] == ["infra", "bundles"] and len(p.split("/")) > 3})
        for bid in bundle_ids:
            if bid == bid.strip().lower() and get_builtin_bundle(bid) is not None:
                vendor_composite_bundle(source, bid)
    except Exception as e:  # noqa: BLE001 - the catalog the developer vendors from cannot be read: no verdict
        raise GateUnavailableError(f"Stage 2 golden-module catalog unavailable: {type(e).__name__}: {e}",
                                   reason="QA_CONTEXT") from e
    return frozenset(p for p, c in head_files.items() if isinstance(c, str) and source.get(p) == c)


def _diagnostic_fingerprint(d: Dict[str, Any]) -> str:
    """(tool, code, file, line). A Stage 2 judge finding is fingerprinted by its typed fields only
    (JUDGE-GATE-ENUMERATED-FINDINGS, owner 11-13): (tool, code, task_id, file, facet), never its text. The judge's
    prose varies between attempts on the same bytes (a judge model that ignores temperature), so the former
    (tool, code, sha256(message)) key (QA-JUDGE-FINGERPRINT) made every retry look like progress and NO_PROGRESS could
    never fire. The typed fields are the repair seed: the attributed plan task (exact DAG task_id), the routed
    committed file and, when a lens labels its findings, the closed-set facet. Two different findings on the same
    target share one key (RT F3, a decision): run_qa then stops at once only when no routed file changed since the
    previous attempt, else it allows one more round. A finding attributed differently (a task or a file
    gained or changed) is a different repair seed, so it counts as progress (this replaces review rule RT F4, which
    kept the routed file out because the key was the text). Every other tool's fingerprint is unchanged. "Judge
    finding" is the gateway's stamp (QA-JUDGE-STAMP, `is_judge_finding`), never the `tool` string: a sandbox
    diagnostic that claims tool "judge" keeps the ordinary (tool, code, file, line) fingerprint."""
    import hashlib

    if _qa_is_judge_finding(d):
        parts = [d.get("tool"), d.get("code")] + [d.get(k) if isinstance(d.get(k), str) else None
                                                  for k in ("task_id", "file", "facet")]
    else:
        parts = [d.get("tool"), d.get("code"), d.get("file"), d.get("line")]
    key = json.dumps(parts, sort_keys=False)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# JUDGE-GATE-ENUMERATED-FINDINGS RT F3: per attempt, sha256 of the committed content of every file a judge finding is
# routed to, and how many consecutive repeats of the same judge repair targets were allowed one more round.
_QA_JUDGE_FILE_SHAS_FIELD = "judge_routed_file_sha256"
_QA_NO_PROGRESS_GRACE_FIELD = "judge_repeat_grace"


def _judge_file_shas(diagnostics: List[Dict[str, Any]], head_files: Dict[str, Any]) -> Dict[str, str]:
    """{routed path: sha256 of its committed text} for the judge findings (gateway stamp) that name a committed file."""
    import hashlib

    out: Dict[str, str] = {}
    for d in diagnostics:
        path = d.get("file")
        if _qa_is_judge_finding(d) and isinstance(path, str) and isinstance(head_files.get(path), str):
            out[path] = hashlib.sha256(head_files[path].encode("utf-8")).hexdigest()
    return out


def _judge_routed_file_changed(prev: Any, current: Dict[str, str]) -> bool:
    """True when a file the current judge findings are routed to has a recorded content hash on the previous attempt
    that differs now. Unrecorded (file-less findings, or a record from before RT F3) is not a change."""
    if not isinstance(prev, dict):
        return False
    return any(isinstance(prev.get(p), str) and prev[p] != sha for p, sha in current.items())


def _judge_task_file(task: Any, head_files: Dict[str, Any]) -> Optional[str]:
    """QA-JUDGE-FINGERPRINT, narrowed by QA-JUDGE-FILE-MAPPING: the task's committed target file when its DAG task names
    exactly ONE exact `target_files` path that exists in the committed tree; None when it names none or several. Before,
    the first of several was taken, so a finding about one file of a multi-file task (testplan01-e2: `.python-version`
    in a task whose first committed target was `requirements.txt`) was pinned to another file."""
    targets = task.get("target_files") if isinstance(task, dict) else None
    committed = {t for t in (targets if isinstance(targets, list) else []) if isinstance(t, str) and t in head_files}
    return next(iter(committed)) if len(committed) == 1 else None


def _judge_finding_file(named: Any, task: Any, head_files: Dict[str, Any]) -> Optional[str]:
    """QA-JUDGE-FILE-MAPPING: the file a missed directive is routed to. 1) The path the judge named in its typed field
    (`missed_directive_files`), when it is exactly a committed path; 2) else the attributed task's single committed
    target file (_judge_task_file); 3) else None: a finding with no resolvable file is never pinned to an arbitrary
    file (QA-FEEDBACK then treats it as file-less: text beside seeded sandbox findings, otherwise regeneration)."""
    if isinstance(named, str) and named in head_files:
        return named
    return _judge_task_file(task, head_files) if task is not None else None


def _judge_security_diagnostic(message: str, named: Any, head_files: Dict[str, Any]) -> Dict[str, Any]:
    """QA-JUDGE-APP-AUTH: one JUDGE.SECURITY finding, routed to the path the judge named only when it is exactly a
    committed path. A named path that is not in the commit is said out loud (warning + `detail`): the finding stays a
    blocking, file-less finding, never dropped and never pinned to another file."""
    path = _judge_finding_file(named, None, head_files)
    detail = None
    if isinstance(named, str) and path is None:
        logger.warning(f"QA security judge named a file that is not in the reviewed commit: {named[:200]!r}")
        detail = f"The QA reviewer named a file that is not in the reviewed commit: {named[:200]!r}. No file was routed."
    return {"tool": "judge", "code": "JUDGE.SECURITY", "severity": "error", "file": path, "line": None,
            "message": message, "detail": detail, _QA_JUDGE_FINDING_FIELD: True}


def _branch_moved(e: BranchMovedError, req: QAVerifyRequest, gate: str) -> PlatformDefectError:
    # FD-4F (red-team F6): an integrity event, not an outage.
    logger.error(
        f"{gate}: branch '{req.branch_name}' of '{req.product_id}' moved (expected {e.expected_sha}, head {e.actual_sha})",
        extra={"security_event": "branch_moved"},
    )
    return PlatformDefectError(
        f"branch '{req.branch_name}' moved after the gatekeeper verified {e.expected_sha} (head is now {e.actual_sha})",
        reason="BRANCH_MOVED",
        details={"expected_commit_sha": e.expected_sha, "actual_commit_sha": e.actual_sha},
    )


def _commit_deploys_cloud_run(head_files: Dict[str, Any]) -> bool:
    """The commit's root module calls the golden compute-cloudrun module (exact parse,
    compute_intent.existing_compute_entries)."""
    from developer_agent.compute_intent import existing_compute_entries

    entries, _unparsed = existing_compute_entries(head_files)
    return any(e.kind == "cloudrun" and e.root for e in entries)


def _commit_builds_container_images(head_files: Dict[str, Any]) -> bool:
    """IMAGE-BUILD-PLATFORM-FACT (ex01-g13): the commit's root module calls a golden compute module of a container kind
    (exact parse, compute_intent.existing_compute_entries; every kind except the VM kinds
    validators.container.NON_CONTAINER_KINDS, the terraform server's own rule for building images). The platform then
    builds the workload's images itself with Cloud Native Buildpacks, so a plan's build file is met by the platform."""
    from developer_agent.compute_intent import existing_compute_entries
    from developer_agent.validators.container import NON_CONTAINER_KINDS

    entries, unparsed = existing_compute_entries(head_files)
    if unparsed:   # RT 6: said out loud (no behavior change: an unparsed file adds no entry, so no fact from it)
        logger.warning(f"IMAGE_BUILD fact: {len(unparsed)} workload IaC file(s) did not parse: {sorted(unparsed)[:10]}")
    return any(e.root and e.kind not in NON_CONTAINER_KINDS for e in entries)


_GKE_ROOT = "infra/workload/"
_GKE_ROOT_MAIN = _GKE_ROOT + "main.tf"
_GKE_ROOT_VARIABLES = _GKE_ROOT + "variables.tf"
_GKE_ROOT_TFVARS = _GKE_ROOT + "terraform.tfvars"
_GKE_ROOT_SUFFIXES = (".tf", ".tf.json", ".tfvars", ".tfvars.json")
_GKE_MODULE_SOURCE = "../modules/compute-gke-autopilot"
# (module argument, its exact platform reference, the variable, the platform's default for it)
_GKE_NETWORK_INPUTS = (("network", "${var.network}", "network", "default"),
                       ("subnetwork", "${var.subnetwork}", "subnetwork", ""))


def _root_file_is_empty(path: str, text: Any) -> bool:
    """A root-module file with no block and no attribute (e.g. the human.tf / human_override.tf stubs: comments only).
    Exact parse (python-hcl2 / json); anything unparsable is not empty."""
    if not isinstance(text, str):
        return False
    if not text.strip():
        return True
    try:
        if path.endswith(".json"):
            doc = json.loads(text)
            return isinstance(doc, dict) and all(k == "//" for k in doc)
        import hcl2  # python-hcl2==7.3.1 (gateway requirements)
        return hcl2.loads(text) == {}
    except Exception:  # noqa: BLE001 - unparsable: not empty
        return False


def _commit_gke_on_default_network(head_files: Dict[str, Any]) -> bool:
    """GKE-NETWORK-PLATFORM-FACT (ex04-1115b): the commit's GKE cluster gets exactly the network the platform renders.
    All of, by exact parse and exact equality (anything else, or anything that does not parse, is False, so the
    network finding stays blocking; fail closed, RT F3):
    - a typed-intent tree (iac_intent_contract.is_intent_tree);
    - every other root-module file of infra/workload/ (.tf / .tf.json / .tfvars / .tfvars.json) is one the platform
      writes (judge_input.platform_rendered_paths, the one ownership predicate), the intent's own render, or holds
      nothing (no block, no attribute): no person's or AI file can pass another network, override the module or a
      variable default, or add a second cluster;
    - the platform main.tf calls the golden GKE Autopilot module, every such call with `network = var.network` and
      `subnetwork = var.subnetwork`; variables.tf declares each once with the defaults "default" and ""; the platform
      terraform.tfvars sets neither."""
    from developer_agent.assembly import index_blocks
    from developer_agent.iac_intent_contract import FACTS_RENDER_PATH, INTENT_PATH, RENDER_PATH, is_intent_tree
    from qa_auditor.judge_input import platform_rendered_paths

    if not is_intent_tree(head_files):
        return False
    rendered = platform_rendered_paths(head_files)
    for path, text in head_files.items():
        if not (isinstance(path, str) and path.startswith(_GKE_ROOT) and "/" not in path[len(_GKE_ROOT):]
                and path.endswith(_GKE_ROOT_SUFFIXES)):
            continue
        if path in rendered or path in (INTENT_PATH, RENDER_PATH, FACTS_RENDER_PATH):
            continue
        if not _root_file_is_empty(path, text):
            return False
    texts = {p: head_files.get(p) for p in (_GKE_ROOT_MAIN, _GKE_ROOT_VARIABLES)}
    if not all(isinstance(t, str) and p in rendered for p, t in texts.items()):
        return False
    tfvars = head_files.get(_GKE_ROOT_TFVARS)
    if tfvars is not None and not (isinstance(tfvars, str) and _GKE_ROOT_TFVARS in rendered):
        return False
    try:
        main_blocks = index_blocks(texts[_GKE_ROOT_MAIN])
        var_blocks = index_blocks(texts[_GKE_ROOT_VARIABLES])
        import hcl2  # python-hcl2==7.3.1 (gateway requirements): the tfvars are attributes, not blocks
        tf_attrs = hcl2.loads(tfvars) if tfvars and tfvars.strip() else {}
    except Exception:  # noqa: BLE001 - unparsable root: not judged, never handled
        return False
    if main_blocks is None or var_blocks is None or not isinstance(tf_attrs, dict):
        return False
    gke = [b for b in main_blocks if b.kind == "module" and (b.body or {}).get("source") == _GKE_MODULE_SOURCE]
    if not gke:
        return False
    for arg, ref, var, default in _GKE_NETWORK_INPUTS:
        if any((b.body or {}).get(arg) != ref for b in gke) or var in tf_attrs:
            return False
        decl = [b for b in var_blocks if b.kind == "variable" and b.labels == (var,)]
        if len(decl) != 1 or (decl[0].body or {}).get("default") != default:
            return False
    return True


def _direct_iap_cloud_run_commit(ingress_policy: Dict[str, Any], head_files: Dict[str, Any]) -> bool:
    """DIRECT-IAP-SKILL-VERIFY: the workload this commit belongs to is PRIVATE_IAP (QA's own resolution, the same as the
    developer's) and the commit's root module calls the golden compute-cloudrun module, the one module with Direct IAP
    (exact parse, compute_intent.existing_compute_entries). Exactly the workloads whose code writers get the IAP rule."""
    from developer_agent.access_resolution import PRIVATE_IAP

    if ingress_policy.get("access_mode") != PRIVATE_IAP:
        return False
    return _commit_deploys_cloud_run(head_files)


_APP_ADMIN_VARIABLES = "infra/workload/variables.tf"


def _commit_app_admin_count(head_files: Dict[str, Any]) -> Optional[int]:
    """APP-ADMIN-IAP-CONTRACT: the number of app administrators the commit's platform-rendered root declares (the
    default of exactly one `variable "app_admin_emails"` block in infra/workload/variables.tf, a list of strings;
    python-hcl2 parse, no text matching), or None when the commit has no such declaration (a build before the contract,
    any other workload) or it does not parse: then the facts carry no admin line. The default is the only value the
    platform supplies (no tfvars key, no deploy-time key)."""
    from developer_agent.assembly import index_blocks
    from developer_agent.terraform_engine import APP_ADMIN_EMAILS_VARIABLE

    text = head_files.get(_APP_ADMIN_VARIABLES)
    if not isinstance(text, str):
        return None
    try:
        blocks = index_blocks(text)
    except Exception:  # noqa: BLE001 - unparsable root: no fact
        return None
    decl = [b for b in blocks or [] if b.kind == "variable" and tuple(b.labels) == (APP_ADMIN_EMAILS_VARIABLE,)]
    if len(decl) != 1:
        return None
    default = (decl[0].body or {}).get("default")
    if not isinstance(default, list) or not all(isinstance(e, str) for e in default):
        return None
    return len(default)


def _stage_two(req: QAVerifyRequest, tree: Any, base_files: Dict[str, Any], backend: Any, evidence_db: Any,
               outcome: Any, deadline: float, *, tests_passed: bool,
               base_branch: str = "main") -> Tuple[Any, Any, Any, Dict[str, Any]]:
    """The Stage 2 dual-lens audit of the committed `tree`: (security result, adherence result, composite report,
    pipeline context). Raises GateUnavailableError / LensUnavailableError. `tests_passed` False
    (QA-STAGE2-ON-TEST-FAIL): the same audit of a build whose sandbox tests failed; only the deterministic report
    (which feeds the composite verdict, not the judges' prompts) says so."""
    ctx = _fetch_pipeline_context_for_qa(req.product_id, req.trace_id, evidence_db, req.task_dag)
    report = outcome.report or {}
    determ = {
        "passed": tests_passed,
        "pytest_success": tests_passed,
        # RT14-17: skipped / xfail tests are not passes
        "pytest_passed_count": (int(report.get("tests_total", 0)) - int(report.get("tests_failed", 0))
                                - int(report.get("tests_skipped", 0))),
        "pytest_failed_count": int(report.get("tests_failed", 0)),
        "bandit_passed": True,
        "zero_dockerfile_passed": True,
        "ast_syntax_passed": True,
        "git_diff_pruned": "",
        "files_inspected": sorted(tree.files_text),
        "summary": outcome.summary,
    }
    # QA-STAGE2-INPUT: the complete changed-file list + plan target states (never truncated) and one
    # budgeted, priority-ordered diff; copied golden modules by name only.
    judge_input = build_judge_input(base_files, tree.files_text, task_dag=ctx["task_dag"],
                                    golden_copies=_platform_golden_copies(tree.files_text),
                                    test_layout_services=ctx.get("service_names"),   # TEST-LAYOUT-PLATFORM-FACT
                                    base_branch=base_branch)   # RT14-28: the workload's recorded base branch
    dag_chars = len(_qa_judge_input.task_dag_json(ctx["task_dag"]))
    if dag_chars > _qa_judge_input.TASK_DAG_BUDGET_CHARS:
        # RT14-29: the adherence judge is shown the whole Task DAG or none of the audit runs (never cut mid-JSON).
        raise GateUnavailableError(
            f"Stage 2 input over budget: the Task DAG is {dag_chars} characters "
            f"(budget {_qa_judge_input.TASK_DAG_BUDGET_CHARS}); it is never cut",
            reason="QA_INPUT_BUDGET",
            details={"task_dag_chars": dag_chars, "task_dag_budget_chars": _qa_judge_input.TASK_DAG_BUDGET_CHARS})
    over = judge_input.workload_not_shown
    if over:
        # Fable RT F1: never judge a workload without its root module, code or tests -> no verdict.
        raise GateUnavailableError(
            f"Stage 2 input over budget: {len(over)} workload file(s) not shown to the judges "
            f"({len(judge_input.shown)} shown, budget {_qa_judge_input.STAGE2_DIFF_BUDGET_CHARS} characters)",
            reason="QA_INPUT_BUDGET",
            details={"not_shown": list(over), "not_shown_count": len(over),
                     "shown_count": len(judge_input.shown), "budget_chars": _qa_judge_input.STAGE2_DIFF_BUDGET_CHARS})
    # QA-STAGE2-PLATFORM-FACTS: typed facts only. VCS = the provider of the source QA fetched this exact
    # commit from; IaC mode = the committed tree's sticky intent rule (iac_intent_contract.is_intent_tree).
    from developer_agent.iac_intent_contract import is_intent_tree
    from qa_auditor.platform_satisfied import platform_handlings

    vcs_kind = getattr(backend, "provider", None)
    # ADHERENCE-PLATFORM-SATISFIED (owner 11-11): the facets the platform handles for this workload, from typed facts
    # only: the workload record (budget ceiling, sandbox lifecycle), and for a Public app whose commit deploys Cloud
    # Run, the per-service access limitation (with the plan-time advisories); {} = none (prompt, schema and verdict
    # as before).
    handled = platform_handlings(
        ctx.get("workload_policy"), ingress_policy=ctx.get("ingress_policy"),
        deploys_cloud_run=_commit_deploys_cloud_run(tree.files_text),
        access_advisories=ctx.get("access_advisories") or [],
        # GKE-NETWORK-PLATFORM-FACT (ex04-1115b): a typed-intent GKE commit on the project's default network
        gke_default_network=_commit_gke_on_default_network(tree.files_text),
        # IMAGE-BUILD-PLATFORM-FACT (ex01-g13): the platform builds this commit's container images itself
        builds_container_images=_commit_builds_container_images(tree.files_text),
        # IAM-POLICY-PLATFORM-FACT (ex02-g13): the plan has an infrastructure task (typed kind, exact rule)
        has_iac_task=any(_qa_judge_input.FACT_IAC in _qa_judge_input.task_fact_kinds(t)
                         for t in (ctx["task_dag"] or [])))
    # SECURITY-LENS-PLATFORM-FACTS (owner 11-13): ONE facts object for every lens (the coordinator refuses to run
    # without it and gives the same object to each lens).
    facts = build_platform_facts(
        vcs_kind if vcs_kind in vcs_ledger.PROVIDERS else None,
        IAC_MODE_GENERATE if is_intent_tree(tree.files_text) else IAC_MODE_OFF,
        ctx["task_dag"],
        # QA-JUDGE-FILE-MAPPING: only when the commit holds the platform's own pin (exact path + content)
        python_runtime_pin=PLATFORM_PYTHON_VERSION if platform_runtime_pins(tree.files_text) else None,
        direct_iap_cloud_run=_direct_iap_cloud_run_commit(ctx["ingress_policy"], tree.files_text),
        app_admin_count=_commit_app_admin_count(tree.files_text),   # APP-ADMIN-IAP-CONTRACT (Direct IAP line only)
        platform_handled=handled,
        test_layout_services=ctx.get("service_names"),   # TEST-LAYOUT-PLATFORM-FACT
        committed_paths=tree.files_text)   # RT F1: the committed platform-rendered set (exact membership)
    remaining = deadline - time.monotonic()
    coordinator = DualLensAuditorCoordinator(
        timeout_seconds=min(STAGE_TWO_DEADLINE_S, max(1.0, remaining - STAGE_TWO_MARGIN_S)))
    sec_res, adh_res, comp_rep = coordinator.evaluate_stage_two(
        git_diff=judge_input.diff,
        file_inventory=judge_input.files,
        platform_facts=facts,
        determ_report=determ,
        task_dag=ctx["task_dag"],
        pytest_logs=_qa_pytest_logs(report),   # RT14-29 / RT14-17: the log tail + the platform's test counts
        ingress_policy=ctx["ingress_policy"],
        compliance_frameworks=ctx["compliance_frameworks"],
        compliance_summary=ctx["compliance_summary"],
        db_client=evidence_db,
        base_branch=base_branch,   # RT14-28
    )
    return sec_res, adh_res, comp_rep, ctx


def _qa_pytest_logs(report: Mapping[str, Any]) -> str:
    """RT14-29 / RT14-17: the adherence judge's TEST_LOGS text = the QA job's log tail, then one line of the platform's
    own test counts from the report (last, so the lens's tail view always keeps it). A skipped or xfail test is never
    counted as passed. Counts that are not non-negative integers are named as unavailable, never guessed."""
    def count(key: str) -> Optional[int]:
        v = report.get(key, 0)
        return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None

    total, failed, skipped = count("tests_total"), count("tests_failed"), count("tests_skipped")
    if total is None or failed is None or skipped is None or failed + skipped > total:
        line = "== QA test counts (platform record): unavailable"
    else:
        line = (f"== QA test counts (platform record): {total} test(s), {total - skipped - failed} passed, "
                f"{failed} failed, {skipped} skipped or xfail (not passes)")
    tail = report.get("logs_tail")
    return f"{tail}\n{line}" if isinstance(tail, str) and tail else line


def _judge_diagnostics(sec_res: Any, adh_res: Any, ctx: Dict[str, Any], head_files: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The judges' blocking findings as QA diagnostics: one JUDGE.SECURITY per critical vulnerability and one
    JUDGE.ADHERENCE per missed directive (JUDGE-GATE-ENUMERATED-FINDINGS: no score finding). Each carries the gateway's
    judge stamp (QA-JUDGE-STAMP: `qa_repair.JUDGE_FINDING_FIELD` = True), a field the QA job's extra="forbid"
    DiagnosticIn cannot carry, so only these findings get the judge treatment (fingerprint, text-only ride-along)."""
    crits = list(sec_res.critical_vulnerabilities)
    crit_files = list(getattr(sec_res, "critical_vulnerability_files", None) or [])   # QA-JUDGE-APP-AUTH
    if len(crit_files) != len(crits):
        crit_files = [None] * len(crits)
    out: List[Dict[str, Any]] = [_judge_security_diagnostic(v, p, head_files) for v, p in zip(crits, crit_files)]
    adh_msgs = list(adh_res.missed_directives)
    if adh_msgs:
        # JUDGE-GATE-ENUMERATED-FINDINGS (owner 11-13): one finding per missed directive, never a score finding (the
        # scores are informational; the coordinator refuses a failed verdict that lists nothing).
        # QA-JUDGE-FILE-MAPPING (was QA-JUDGE-FINGERPRINT's first-target rule): a missed directive goes to the exact
        # committed path the judge named, else to its attributed task's single committed target, else to no file.
        task_ids = list(getattr(adh_res, "missed_directive_task_ids", None) or [])
        if len(task_ids) != len(adh_msgs):
            task_ids = [None] * len(adh_msgs)
        named = list(getattr(adh_res, "missed_directive_files", None) or [])
        if len(named) != len(adh_msgs):
            named = [None] * len(adh_msgs)
        tasks_by_id: Dict[str, Any] = {}
        for t in ctx["task_dag"]:
            if isinstance(t, dict) and isinstance(t.get("task_id"), str):
                tasks_by_id.setdefault(t["task_id"], t)
        # JUDGE-NAMED-INTENT-REMOVAL: the intent entries each directive says to delete (typed field, same position);
        # kept only on a finding routed to the intent or its render (RT F5: the plan seeds that on the intent) and only
        # when exactly an entry of the committed intent
        addrs = list(getattr(adh_res, "missed_directive_removals", None) or [])
        if len(addrs) != len(adh_msgs):
            addrs = [[]] * len(adh_msgs)
        for m, tid, path, addr in zip(adh_msgs, task_ids, named, addrs):
            diag = {"tool": "judge", "code": "JUDGE.ADHERENCE", "severity": "error",
                    "file": _judge_finding_file(path, tasks_by_id.get(tid) if tid else None, head_files),
                    "line": None, "message": m, "detail": None, _QA_JUDGE_FINDING_FIELD: True}
            if tid:
                diag["task_id"] = tid
            if diag["file"] in (_QA_INTENT_PATH, _QA_INTENT_RENDER_PATH) and isinstance(addr, list) and addr:
                kept = _qa_judge_named_intent_removals({**diag, _QA_JUDGE_REMOVALS_FIELD: list(addr)},
                                                        head_files.get(_QA_INTENT_PATH))
                if kept:
                    diag[_QA_JUDGE_REMOVALS_FIELD] = list(kept)
            out.append(diag)
    return out


def _stage_two_on_test_fail(req: QAVerifyRequest, tree: Any, base_files: Dict[str, Any], backend: Any,
                            evidence_db: Any, outcome: Any, deadline: float, base_branch: str = "main"
                            ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """QA-STAGE2-ON-TEST-FAIL (register row, owner 10-28; gateway only): Stage 2 on a build whose sandbox tests failed
    (CODE_DEFECT). Returns (the evidence record's `stage2_on_test_fail` entry, the judges' blocking findings). Never
    raises and never changes the Stage 1 verdict: a judge that is unavailable, out of time or missing its context
    adds nothing (the test failures still go to the repair round). Time: the pass path's own rule -- it starts only
    when STAGE_TWO_MIN_REMAINING_S is left and is given min(STAGE_TWO_DEADLINE_S, remaining - STAGE_TWO_MARGIN_S),
    so the request stays inside QA_REQUEST_DEADLINE_S."""
    if deadline - time.monotonic() < STAGE_TWO_MIN_REMAINING_S:
        logger.warning(f"QA Stage 2 on a failed test run skipped for '{req.product_id}' (trace {req.trace_id}): "
                       f"not enough time left")
        return {"status": "SKIPPED", "reason": "DEADLINE", "findings": 0}, []
    try:
        sec_res, adh_res, _comp, ctx = _stage_two(req, tree, base_files, backend, evidence_db, outcome, deadline,
                                                  tests_passed=False, base_branch=base_branch)
        blocking = not (sec_res.passed and adh_res.passed)
        found = _judge_diagnostics(sec_res, adh_res, ctx, tree.files_text) if blocking else []
    except stage_deadline.STOP_ERRORS:
        raise   # RT F1: a stage stop is not a judge outage (it ends the stage, typed)
    except GateUnavailableError as ge:
        status, reason, detail = "UNAVAILABLE", ge.reason, ge.message
    except LensUnavailableError as le:
        status, reason, detail = "UNAVAILABLE", "STAGE2_UNAVAILABLE", str(le)
    except Exception as e:  # noqa: BLE001 - the judges never block the test failures' repair
        status, reason, detail = "UNAVAILABLE", "STAGE2_ERROR", type(e).__name__
    else:
        logger.info(f"QA Stage 2 on a failed test run for '{req.product_id}' (trace {req.trace_id}): "
                    f"{len(found)} blocking finding(s)")
        return ({"status": "BLOCKING" if blocking else "CLEAN", "reason": None, "findings": len(found),
                 "security_lens": sec_res.model_dump(), "adherence_lens": adh_res.model_dump()}, found)
    logger.warning(f"QA Stage 2 on a failed test run unavailable for '{req.product_id}' (trace {req.trace_id}): "
                   f"{reason}; the test failures alone go to the repair round")
    return {"status": status, "reason": reason, "summary": detail, "findings": 0}, []


def _log_judge_findings(req: QAVerifyRequest, reason: Optional[str], diagnostics: List[Dict[str, Any]]) -> None:
    """QA-STAGE2-ONLY-REPAIR F2 (audit): one INFO line per Stage 2 judge finding of this attempt with its typed facts
    only -- code, the routed file (or none) and the attributed task_id (or none); never the finding's text. The QA
    record is overwritten per attempt, so these lines are what shows after the run why the developer repaired or
    regenerated (qa_repair.plan_qa_repair decides on exactly these fields)."""
    judged = [d for d in diagnostics if d.get(_QA_JUDGE_FINDING_FIELD) is True]
    for n, d in enumerate(judged, 1):
        path, tid = d.get("file"), d.get("task_id")
        facts = {"product_id": req.product_id, "trace_id": req.trace_id, "attempt": req.attempt, "qa_reason": reason,
                 "finding": n, "findings": len(judged), "code": d.get("code"),
                 "file": path if isinstance(path, str) else None, "task_id": tid if isinstance(tid, str) else None}
        logger.info(f"QA Stage 2 finding {n}/{len(judged)} for '{req.product_id}' (trace {req.trace_id}, attempt "
                    f"{req.attempt}, {reason}): code {facts['code']!r}, file {facts['file'] or 'none'!r}, "
                    f"task_id {facts['task_id'] or 'none'!r}", extra={"qa_stage2_finding": facts})


def _qa_base_branch(evidence_db: Any, product_id: str) -> str:
    """RT14-28: the workload's recorded base branch (handler.workflow_branch of workloads/{pid}.default_branch, the
    branch the developer cut the commit from and opened its PR against); "main" when none is recorded. An unreadable
    record is GATE_UNAVAILABLE WORKLOAD_RECORD_UNREADABLE, never "main" by guess."""
    try:
        wdata = _read_workload(evidence_db, product_id) or {}
    except Exception as e:
        raise GateUnavailableError(f"QA could not read workloads/{product_id} for its base branch ({type(e).__name__})",
                                   reason="WORKLOAD_RECORD_UNREADABLE") from e
    return _recorded_base_branch(wdata)


def run_qa(req: QAVerifyRequest, *, client: Any, source_backend_factory: Any, evidence_db: Any) -> Dict[str, Any]:
    """Runs the isolated QA job + Stage 2, persists evidence, returns the response body.

    Returns a body only for a verdict (pass, or CODE_DEFECT with diagnostics). Raises GateUnavailableError /
    PlatformDefectError for everything else (-> non-2xx -> DLQ). Never returns a pass it did not observe.
    """
    sd = stage_deadline.current()   # STAGE-DEADLINE: the stage's own deadline (same clock, time.monotonic)
    deadline = sd.deadline if sd is not None else time.monotonic() + QA_REQUEST_DEADLINE_S
    if client is None:
        raise GateUnavailableError(
            "QA job not configured (QA_* env unset; the isolated QA job ships with FD-4F Stage A)",
            reason="QA_NOT_CONFIGURED",
        )
    if evidence_db is None:
        raise GateUnavailableError("QA evidence store (Firestore) unavailable", reason="EVIDENCE_STORE")

    try:
        backend = source_backend_factory(req.product_id)
        tree = fetch_tree_at_head(backend, req.branch_name, req.expected_commit_sha)
    except BranchMovedError as e:
        raise _branch_moved(e, req, "QA") from e
    except BranchFetchError as e:
        raise GateUnavailableError(f"QA could not fetch the committed tree: {e}", reason="SOURCE_FETCH") from e

    # RT14-28: the diff base is the workload's recorded base branch (was always "main"), and only a typed "no such
    # branch" or an empty tree is an empty base; any other fetch failure stops QA (never every file judged as new).
    base_branch = _qa_base_branch(evidence_db, req.product_id)
    try:
        base_files = fetch_tree_at_head(backend, base_branch).files_text
    except GitServerUnreachable as e:
        # GIT-404-TYPED-DIRECT-CALLERS: a 404 the git server did not send is not "no main yet"; never an empty base.
        raise GateUnavailableError(f"QA could not read the diff base '{base_branch}': {e}",
                                   reason=GitServerUnreachable.error_class) from e
    except (BranchNotFoundError, EmptyArchiveError) as e:
        # Diff base only (Stage 2 context). No base branch / an empty one = first run; the judges see every file added.
        logger.warning(f"QA diff base '{base_branch}' of '{req.product_id}' is absent or empty ({e.error_class}); "
                       "diffing against an empty base")
        base_files = {}
    except BranchFetchError as e:
        raise GateUnavailableError(f"QA could not read the diff base '{base_branch}': {e}", reason="SOURCE_FETCH",
                                   details={"base_branch": base_branch}) from e

    stage_deadline.checkpoint("qa.job")   # RT F1: no QA job start after a stage stop (no-op without a deadline)
    outcome = client.run(
        tar_bytes=tree.tar_bytes, commit_sha=tree.commit_sha, trace_id=req.trace_id,
        product_id=req.product_id, deadline=deadline,
    )

    doc: Dict[str, Any] = {
        "trace_id": req.trace_id,
        "product_id": req.product_id,
        "branch_name": req.branch_name,
        "commit_sha": tree.commit_sha,
        "attempt": req.attempt,
        "nonce": outcome.nonce,
        "execution_name": outcome.execution_name,
        "exit_code": outcome.exit_code,
        "static": outcome.static,
        "report": outcome.report,
        "skipped_binary_files": tree.skipped_binary,
        "executed_at": datetime.now(timezone.utc).isoformat(),
    }
    diagnostics: List[Dict[str, Any]] = list(outcome.diagnostics)
    passed = False
    error_class: Optional[str] = outcome.error_class.value if outcome.error_class else None
    summary = outcome.summary
    reason = outcome.reason

    if outcome.passed:
        if deadline - time.monotonic() < STAGE_TWO_MIN_REMAINING_S:
            error_class, reason, summary = ErrorClass.GATE_UNAVAILABLE.value, "DEADLINE", "no time left for the Stage 2 audit"
        else:
            stage_deadline.checkpoint("qa.stage_two")   # RT F1
            try:
                sec_res, adh_res, comp_rep, ctx = _stage_two(req, tree, base_files, backend, evidence_db, outcome,
                                                             deadline, tests_passed=True, base_branch=base_branch)
                doc["security_lens"] = sec_res.model_dump()
                doc["adherence_lens"] = adh_res.model_dump()
                doc["composite_audit"] = comp_rep.model_dump()
                summary = comp_rep.summary
                if comp_rep.passed:
                    passed, error_class, reason = True, None, None
                else:
                    error_class, reason = ErrorClass.CODE_DEFECT.value, _QA_STAGE2_FAILED
                    diagnostics.extend(_judge_diagnostics(sec_res, adh_res, ctx, tree.files_text))
            except GateUnavailableError as ge:
                error_class, reason, summary = ErrorClass.GATE_UNAVAILABLE.value, ge.reason, ge.message
                if ge.details:
                    doc["stage2_unavailable_details"] = dict(ge.details)   # e.g. QA_INPUT_BUDGET: the files left out
            except LensUnavailableError as le:
                error_class, reason, summary = ErrorClass.GATE_UNAVAILABLE.value, "STAGE2_UNAVAILABLE", str(le)
    elif error_class == ErrorClass.CODE_DEFECT.value:
        # QA-STAGE2-ON-TEST-FAIL (owner 10-28): the sandbox tests failed -> the judges also review this same build, so
        # the next repair round gets both (QA-RETRIES: up to 3 rounds). The Stage 1 verdict (class, reason, retryable) never depends on Stage 2.
        stage_deadline.checkpoint("qa.stage_two")   # RT F1
        doc["stage2_on_test_fail"], found = _stage_two_on_test_fail(req, tree, base_files, backend, evidence_db,
                                                                    outcome, deadline, base_branch=base_branch)
        if found:
            diagnostics.extend(found)   # after Stage 1's, so the test failures keep the feedback block's room first
            summary = f"{summary}; QA reviewer (Stage 2) on the same build: {len(found)} blocking finding(s)"

    for d in diagnostics:
        d["source"] = "qa"
        d["iteration"] = req.attempt
        d["fingerprint"] = _diagnostic_fingerprint(d)

    retryable = error_class == ErrorClass.CODE_DEFECT.value
    evidence_ref = evidence_db.collection("qa_test_runs").document(req.trace_id)
    judge_file_shas = _judge_file_shas(diagnostics, tree.files_text)   # RT F3: routed files' committed content
    no_progress_grace = 0
    if retryable:
        # FD-4F (red-team F3): a retry whose diagnostic set equals the previous attempt's made no progress -> stop.
        try:
            prev = evidence_ref.get()
            prev_data = (prev.to_dict() or {}) if prev.exists else {}
        except Exception as e:
            raise GateUnavailableError(f"QA evidence read failed: {type(e).__name__}: {e}", reason="EVIDENCE_STORE") from e
        current_fps = sorted(d["fingerprint"] for d in diagnostics)
        if (
            prev_data.get("error_class") == ErrorClass.CODE_DEFECT.value
            and int(prev_data.get("attempt", -1)) < req.attempt
            and sorted(prev_data.get("fingerprints") or []) == current_fps
        ):
            prev_attempt = prev_data.get("attempt")
            if not any(_qa_is_judge_finding(d) for d in diagnostics):
                retryable, reason = False, "NO_PROGRESS"
                summary = f"{summary} (identical diagnostics to attempt {prev_attempt}: no progress, not retrying)"
            else:
                # JUDGE-GATE-ENUMERATED-FINDINGS RT F3: a judge fingerprint is the typed repair target (code, task,
                # file), so a different finding on the same target matches too. Stop at once only when no routed file
                # changed since that attempt (the developer changed nothing where the findings point); when one did,
                # allow one more round and stop on the second consecutive repeat (bounded by the workflow's retries).
                changed = _judge_routed_file_changed(prev_data.get(_QA_JUDGE_FILE_SHAS_FIELD), judge_file_shas)
                prev_grace = prev_data.get(_QA_NO_PROGRESS_GRACE_FIELD)
                prev_grace = prev_grace if isinstance(prev_grace, int) and not isinstance(prev_grace, bool) else 0
                if changed and prev_grace < 1:
                    no_progress_grace = prev_grace + 1
                    summary = (f"{summary} (the same repair targets (code, task, file) as attempt {prev_attempt}, but "
                               f"a routed file changed since: one more round)")
                else:
                    retryable, reason = False, "NO_PROGRESS"
                    summary = (f"{summary} (the same repair targets (code, task, file) as attempt {prev_attempt}"
                               + (", repeated after one more round" if changed else ", with no routed file changed")
                               + ": no progress, not retrying)")
    _log_judge_findings(req, reason, diagnostics)  # after the no-progress check, so the line carries the final reason

    doc.update({
        "passed": passed,
        "error_class": error_class,
        "reason": reason,
        "retryable": retryable,
        "summary": summary,
        "diagnostics": diagnostics,
        "fingerprints": sorted(d["fingerprint"] for d in diagnostics),
        _QA_JUDGE_FILE_SHAS_FIELD: judge_file_shas,
        _QA_NO_PROGRESS_GRACE_FIELD: no_progress_grace,
    })
    # RT F1: nothing is written after the stage answered, the run ended, the job was superseded or the emergency stop
    # is on (reserve 0: a single document write).
    stage_deadline.guard_side_effect("qa.evidence", reserve_s=0)
    try:
        evidence_ref.set(doc)  # full overwrite, never merge: no stale keys from an earlier attempt (H7)
    except Exception as e:
        raise GateUnavailableError(f"QA evidence write failed: {type(e).__name__}: {e}", reason="EVIDENCE_STORE") from e

    record_qa_sign_off_on_plan(evidence_db, req.product_id, req.branch_name, passed, summary, req.trace_id, error_class)

    if error_class == ErrorClass.GATE_UNAVAILABLE.value:
        raise GateUnavailableError(summary, reason=reason, diagnostics=diagnostics,
                                   details={"commit_sha": tree.commit_sha, "execution_name": outcome.execution_name})
    if error_class == ErrorClass.PLATFORM_DEFECT.value:
        raise PlatformDefectError(summary, reason=reason, diagnostics=diagnostics,
                                  details={"commit_sha": tree.commit_sha, "execution_name": outcome.execution_name})
    return {
        "status": "SUCCESS" if passed else "FAILED",
        "passed": passed,
        "error_class": error_class,
        "reason": reason,
        "retryable": retryable,
        "product_id": req.product_id,
        "branch_name": req.branch_name,
        "commit_sha": tree.commit_sha,
        "attempt": req.attempt,
        "summary": summary,
        "diagnostics": diagnostics,
        "outputs": {k: doc.get(k) for k in ("execution_name", "exit_code", "static", "report", "composite_audit")},
    }


def run_qa_verify_in_background(req: AsyncQAVerifyRequest, client: Any, source_backend_factory: Any, evidence_db: Any):
    with AgentLifecycle("QA-Reviewer", req.product_id, req.trace_id, mode="ASYNC CALLBACK") as agent:
        with guaranteed_callback_scope(
            callback_url=req.callback_url,
            trace_id=req.trace_id,
            stage_name="qa",
            product_id=req.product_id,
            firestore_db=evidence_db,
        ) as outcome:
            try:
                body = run_qa(req, client=client, source_backend_factory=source_backend_factory, evidence_db=evidence_db)
            except GateError as ge:
                body = ge.to_body(product_id=req.product_id, branch_name=req.branch_name)
            outcome.update(body)
            outcome["outputs"] = body.get("outputs", {})
            outcome["error"] = None if body.get("passed") else body.get("summary")
            agent.set_summary(body.get("summary", ""), status=body["status"])


@app.post("/agent/qa/verify-async", status_code=status.HTTP_202_ACCEPTED)
def qa_verify_async(
    req: AsyncQAVerifyRequest,
    background_tasks: BackgroundTasks,
    client: Any = Depends(get_qa_job_client),
    source_backend_factory: Any = Depends(get_source_backend_factory),
    evidence_db: Any = Depends(get_evidence_db),
):
    """
    Asynchronously executes QA verification and notifies Cloud Workflows via callback.
    Kept only until the workflow switches to the synchronous route (FD-4F Stage A), then deleted.

    FD-4F (red-team F1): when QA is not configured this returns 503 AT DISPATCH. The pre-Stage-A workflow has no
    `try` on this step, so the execution stops immediately with zero LLM spend, instead of receiving a FAILED
    callback that its QA-retry branch would turn into three blind developer regenerations.
    """
    if client is None:
        raise GateUnavailableError(
            "QA job not configured (QA_* env unset; the isolated QA job ships with FD-4F Stage A)",
            reason="QA_NOT_CONFIGURED",
        )
    background_tasks.add_task(run_qa_verify_in_background, req, client, source_backend_factory, evidence_db)
    return {
        "status": "ACCEPTED",
        "product_id": req.product_id,
        "trace_id": req.trace_id,
        "message": "QA verification dispatched to background worker. Workflow will resume via callback.",
    }


@app.post("/agent/qa/verify")
def qa_verify(
    req: QAVerifyRequest,
    client: Any = Depends(get_qa_job_client),
    source_backend_factory: Any = Depends(get_source_backend_factory),
    evidence_db: Any = Depends(get_evidence_db),
):
    """
    Step 5 of castor_main_orchestrator (synchronous form, FD-4F W5): stages the commit-bound tree, runs the isolated
    QA job, then the Stage 2 Dual-Lens audit. 200 = verdict (pass, or CODE_DEFECT with diagnostics);
    503 = GATE_UNAVAILABLE / PLATFORM_DEFECT (the run stops). STAGE-DEADLINE: under its SYNC stage deadline (1500 s,
    the former QA_REQUEST_DEADLINE_S), which run_qa's own Stage 2 budget reads.
    """
    return _run_stage("qa", StageMode.SYNC, req.trace_id, req.product_id,
                      lambda: _qa_verify_body(req, client, source_backend_factory, evidence_db))


@app.post("/agent/qa/verify-job", status_code=status.HTTP_202_ACCEPTED)
def qa_verify_job(req: AsyncQAVerifyRequest):
    """Step 5 (LONG-STAGE-CALLBACK): 202 once the stage-runner execution exists; QA's verdict (or typed failure)
    arrives on `callback_url`. The QA client, source backend and evidence store are built inside the job."""
    return _submit_stage_job("qa", req)


def _qa_verify_body(req: QAVerifyRequest, client: Any, source_backend_factory: Any, evidence_db: Any,
                    mode: str = "SYNC") -> Dict[str, Any]:
    with AgentLifecycle("QA-Reviewer", req.product_id, req.trace_id, mode=mode) as agent:
        body = run_qa(req, client=client, source_backend_factory=source_backend_factory, evidence_db=evidence_db)
        agent.set_summary(body["summary"], status=body["status"])
        return body


def _qa_evidence_problems(qa_data: Dict[str, Any], req: ReleasePromoteRequest, trace_id: str, source_backend_factory: Any) -> List[str]:
    """FD-4F (RL-1, D7, D10): reasons the QA evidence cannot authorize an auto-merge. Empty list = usable.

    The release only auto-merges the exact commit QA tested: evidence for this trace and branch, passed with no
    error_class, a full commit SHA equal to the gatekeeper's (when the workflow sends it) and to the CURRENT head.
    The merge itself is pinned to that commit too, which closes the check-then-merge window (plan R7): GitHub merges
    at sha=<ledger head>, the git server at expected_source_sha=<ledger head> (SERVERLESS-AUTOMERGE-SHA)."""
    if not qa_data:
        return ["No QA evidence for this trace"]
    problems: List[str] = []
    if qa_data.get("trace_id") != trace_id:
        problems.append("QA evidence belongs to a different trace")
    if qa_data.get("branch_name") != req.branch_name:
        problems.append("QA evidence is for a different branch")
    if qa_data.get("passed") is not True or qa_data.get("error_class"):
        problems.append(f"QA did not pass ({qa_data.get('error_class') or 'failed'})")
    sha = qa_data.get("commit_sha")
    if not is_commit_sha(sha):
        problems.append("QA evidence is not bound to a commit SHA")
        return problems
    if req.expected_commit_sha is not None and req.expected_commit_sha != sha:
        problems.append(f"QA tested {sha}, gatekeeper verified {req.expected_commit_sha}")
    try:
        head = source_backend_factory(req.product_id).head_sha(req.branch_name)
    except BranchFetchError as e:
        problems.append(f"Could not confirm the branch head ({e})")
        return problems
    if head != sha:
        logger.error(
            f"Release: branch '{req.branch_name}' head {head} != QA-tested {sha}", extra={"security_event": "branch_moved"}
        )
        problems.append(f"Branch head {head} is not the QA-tested commit {sha}")
    return problems


def _release_vcs(vcs_kind: str, product_id: str, full_repo_name: str) -> Any:
    from shared.vcs_provider import VCSProviderFactory

    return VCSProviderFactory.get_provider(provider_name=vcs_kind, default_owner=developer_agent.github_owner,
                                           project_id=developer_agent.project_id, product_id=product_id,
                                           full_repo_name=full_repo_name)


def _release_merge(vcs_kind: str, entry: Dict[str, Any], product_id: str, commit_message: str) -> Dict[str, Any]:
    """FD-4BB: merge exactly the ledger entry. GitHub: the provider re-checks the live PR (same repo, no fork, head
    ref / base ref / head SHA) and merges at the ledger SHA. Serverless Git (single-tenant, no forks, no PR
    objects): fast-forward merge of exactly the ledger branch into the ledger base (QA already confirmed the live
    head equals the QA-tested commit, which equals the ledger SHA). Raises on anything but a confirmed merge.
    FD-4BE: the git server's fast-forward-only 409 (base advanced since the branch was cut) -> MainMovedError.
    SERVERLESS-AUTOMERGE-SHA: the merge names the ledger head (the QA-tested commit) as expected_source_sha, so the
    git server refuses a branch that moved after QA (ServerlessGitSourceMoved, a PRIdentityMismatch on head_sha:
    the same path as GitHub's moved-head 409). A merge the server did not confirm as checked for exactly that
    commit -> SourceCheckUnconfirmedError (the caller only auto-merges after merge_source_check_supported())."""
    # STAGE-DEADLINE orphan guard (RT S2: below the docstring): no merge once the release stage has answered or could
    # not finish in its budget
    stage_deadline.guard_side_effect("release.merge")
    vcs = _release_vcs(vcs_kind, product_id, entry["repo_full_name"])
    if vcs_kind == vcs_ledger.PROVIDER_GITHUB:
        # GHA-PLATFORM-MERGE-SKIP-ACTIONS: the platform builds and applies this merge itself, so the merge commit
        # carries GitHub's skip directive (no Actions Day-2 deploy racing the apply). Serverless Git: unchanged.
        res = vcs.merge_pull_request(entry["repo_full_name"], expected=vcs_ledger.identity(entry),
                                     commit_message=vcs_ledger.github_platform_merge_message(commit_message))
    else:
        try:
            res = vcs.merge_pull_request(entry["repo_full_name"], pr_number=0, commit_message=commit_message,
                                         source_branch=entry["branch"], target_branch=entry["base_branch"],
                                         expected_source_sha=entry["head_sha"])
        except ServerlessGitMergeConflict as conflict:
            raise MainMovedError(
                f"{entry['base_branch']} moved since the branch was cut; nothing merged, re-run the workload",
                reason="MAIN_MOVED", stage="release",
                details={"branch_name": entry["branch"], "base_branch": entry["base_branch"]}) from conflict
    if not (isinstance(res, dict) and res.get("merged") is True and res.get("status") in ("MERGED", "ALREADY_UP_TO_DATE")):
        raise PRMergeNotCompleted(f"merge not confirmed: {res!r}")
    if vcs_kind != vcs_ledger.PROVIDER_GITHUB and res.get("source_sha_checked") is not True:
        raise SourceCheckUnconfirmedError(
            f"the git server reported the merge of {entry['branch']} into {entry['base_branch']} without confirming "
            f"it checked the QA-tested commit {entry['head_sha']}; deploy stopped, check the git server version",
            reason="SOURCE_CHECK_UNCONFIRMED", stage="release",
            details={"branch_name": entry["branch"], "base_branch": entry["base_branch"],
                     "commit_sha": res.get("commit_sha")})
    return res


# SERVERLESS-HITL-WORDING: why a release that the workload lets merge by itself still waits for a person on
# Serverless Git. The code is stored on the approval record (`hitl_reason_code`) and in the release response; the
# text is what the log line, the approval card and the release certificate show.
# SERVERLESS-AUTOMERGE-SHA: a Serverless Git release merges by itself only when the git server confirms, before the
# merge, that it refuses a release branch that changed after QA (merge_source_check_supported). Otherwise:
SERVERLESS_HITL_CHECK_UNSUPPORTED = "SERVERLESS_GIT_SOURCE_CHECK_UNSUPPORTED"   # older git server (no such check)
SERVERLESS_HITL_CHECK_UNCONFIRMED = "SERVERLESS_GIT_SOURCE_CHECK_UNCONFIRMED"   # the git server could not be asked
SERVERLESS_HITL_REASONS: Dict[str, str] = {
    SERVERLESS_HITL_CHECK_UNSUPPORTED: (
        "Serverless Git release needs a human approval, even though the workload does not require code review: "
        "this install's git server cannot refuse a release branch that changed after QA tested it (update the git "
        "server to let releases merge by themselves)"),
    SERVERLESS_HITL_CHECK_UNCONFIRMED: (
        "Serverless Git release needs a human approval, even though the workload does not require code review: "
        "the git server could not be asked whether it refuses a release branch that changed after QA tested it"),
}


def _serverless_source_check_gap(product_id: str, full_repo_name: str) -> Tuple[Optional[str], Optional[str]]:
    """SERVERLESS-AUTOMERGE-SHA: (None, None) when the git server confirms its merge refuses a source branch that
    is not the expected (QA-tested) commit; otherwise the typed code and the plain reason the release keeps its
    human approval. Asked on every release (no cache), before any merge: an older server is never trusted.
    RT F4: only a provider / transport error keeps the approval (the card names it); anything else is a defect of
    the platform itself and stops the release typed (PLATFORM_DEFECT), never a 24 h approval card."""
    try:
        supported = _release_vcs(vcs_ledger.PROVIDER_SERVERLESS_GIT, product_id,
                                 full_repo_name).merge_source_check_supported()
    except _SOURCE_CHECK_PROBE_ERRORS as e:  # the safe side: the release waits for a person, and the card says why
        logger.warning(f"Release '{product_id}': git server capabilities not readable ({type(e).__name__}: {e}); "
                       "the release keeps its human approval")
        reason = f"{SERVERLESS_HITL_REASONS[SERVERLESS_HITL_CHECK_UNCONFIRMED]} ({type(e).__name__}: {e})"
        return SERVERLESS_HITL_CHECK_UNCONFIRMED, reason
    except Exception as e:  # noqa: BLE001 - RT F4: not a git-server answer: typed, never a card
        raise PlatformDefectError(f"release: git server capability check failed ({type(e).__name__}: {e})",
                                  reason="SOURCE_CHECK_PROBE_FAILED", stage="release") from e
    if supported is True:
        return None, None
    return SERVERLESS_HITL_CHECK_UNSUPPORTED, SERVERLESS_HITL_REASONS[SERVERLESS_HITL_CHECK_UNSUPPORTED]


def _release_hitl_action(gate_decision: Any, serverless_hitl_reason: Optional[str]) -> str:
    """The plain cause of a release left for a person (log line and approval card). A Serverless Git approval that
    only the git-server rule requires names that rule, never the workload policy (the workload asked for none)."""
    if gate_decision is not None and gate_decision.recommended_action == "BLOCK_FOR_HITL_REVIEW":
        return serverless_hitl_reason or "HITL enforced by workload policy"
    return "Policy or QA Gatekeeper Blocked"


def _merged_stage_summary(verb: str, ledger_entry: Dict[str, Any], where: str) -> str:
    base = ledger_entry.get("base_branch")
    into = f" into {base}" if isinstance(base, str) and base else ""
    return f"{verb}{into} {where} (no human review required)"


def _record_release_stage_merged(db: Any, trace_id: str, summary: str) -> None:
    """RELEASE-STAGE-OUTCOME (FD-4DT): a release this step merged itself (no approval card), or found already merged,
    records its outcome on pipeline_executions/{trace}.stages.release; a human-reviewed release is recorded by the
    Control Center decision (apps/control-center/routes/approvals.py::_record_release_stage).
    Display record only (the PR ledger holds the merge), so a failed write is logged, never raised."""
    try:
        db.collection("pipeline_executions").document(trace_id).set(
            {"stages": {"release": {"status": "SUCCESS", "summary": summary}}}, merge=True)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Release stage of {trace_id} not recorded after the auto-merge: {type(e).__name__}: {e}")


@app.post("/agent/release/promote")
def release_promote(req: ReleasePromoteRequest, source_backend_factory: Any = Depends(get_source_backend_factory)):
    """Step 6: the release under its SYNC stage deadline (STAGE-DEADLINE; the merge is a guarded side effect)."""
    return _run_stage("release", StageMode.SYNC, req.trace_id, req.product_id,
                      lambda: _release_promote_body(req, source_backend_factory))


def _release_promote_body(req: ReleasePromoteRequest, source_backend_factory: Any):
    """
    Invoked by Step 6 of castor_main_orchestrator workflow.
    Checks workload governance policy:
    - If require_human_code_review == False: automatically merges the PR into main!
    - If require_human_code_review == True: leaves PR open on GitHub for human review!
    """
    trace_id = req.trace_id  # FD-4F (QA-5): required + validated; no "auto-release-trace" default
    with AgentLifecycle("Release-Promotion", req.product_id, trace_id, mode="SYNC") as agent:
        logger.info(f"Executing Release promotion for branch '{req.branch_name}' on product '{req.product_id}'")

        full_repo_name = developer_agent.get_full_repo_name(req.product_id)
        project_id = os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT") or ""

        # ---- FD-4P / FD-4BB begin: workload policy + the PR ledger entry (what StackVend created) ----
        db = None
        try:
            from google.cloud import firestore

            db = firestore.Client(project=project_id) if project_id else None
        except Exception as e:
            logger.warning(f"Release store client unavailable: {e}")
        if db is None:
            raise GateUnavailableError("release: workload / PR ledger store unavailable", reason="STORE_UNAVAILABLE",
                                       stage="release")
        try:
            wdata = _read_workload(db, req.product_id)
        except Exception as e:
            raise GateUnavailableError(f"release: workload unreadable ({type(e).__name__})", reason="STORE_UNAVAILABLE",
                                       stage="release") from e
        if wdata is None:
            raise ReleaseRefusedError(f"release: workload {req.product_id} not found", reason="WORKLOAD_NOT_FOUND",
                                      stage="release")
        vcs_provider = _workload_vcs_kind(wdata)
        if vcs_provider is None:
            raise ReleaseRefusedError(f"release: unsupported vcs_provider {wdata.get('vcs_provider')!r}",
                                      reason="VCS_PROVIDER_UNKNOWN", stage="release")
        try:
            ledger_entry = vcs_ledger.require_entry(db, provider=vcs_provider, repo_full_name=full_repo_name,
                                                    branch=req.branch_name, product_id=req.product_id,
                                                    trace_id=trace_id, mergeable=False)
            if ledger_entry.get("state") not in vcs_ledger.MERGEABLE_STATES and ledger_entry.get("state") != vcs_ledger.STATE_MERGED:
                raise vcs_ledger.LedgerMismatch(f"ledger entry state {ledger_entry.get('state')!r} is not mergeable",
                                                reason="LEDGER_STATE")
        except vcs_ledger.LedgerUnavailable as e:
            raise GateUnavailableError(f"release: {e}", reason="LEDGER_UNAVAILABLE", stage="release") from e
        except vcs_ledger.LedgerError as e:
            # No entry, or one that names another product / trace / repository / provider, or is not mergeable:
            # StackVend did not create this change for this run, so nothing is merged and no approval card is made.
            raise ReleaseRefusedError(f"release: {e}", reason=e.reason, stage="release",
                                      details={"branch_name": req.branch_name, "repo": full_repo_name}) from e

        if ledger_entry.get("state") == vcs_ledger.STATE_MERGED:
            # RT F4: this run's change is already merged (an operator re-invoked the release after the merge, or
            # the process died after recording it). Idempotent: report the merge, never merge again.
            if ledger_entry.get("source_check_confirmed") is False:
                # SERVERLESS-AUTOMERGE-SHA RT F1: the git server merged without confirming the tested-commit check
                # (SourceCheckUnconfirmedError); a re-invoke never turns that into a reported auto-merge / deploy.
                raise ReleaseRefusedError(
                    f"release: {req.branch_name} was merged without the git server confirming it was the QA-tested "
                    f"commit {ledger_entry.get('head_sha')}; nothing is deployed from it, re-run the workload",
                    reason="MERGE_UNCONFIRMED", stage="release",
                    details={"branch_name": req.branch_name, "repo": full_repo_name})
            if vcs_provider == vcs_ledger.PROVIDER_SERVERLESS_GIT:
                merged_url = ""  # install-polish: no browsable page for a Serverless Git branch (see below)
            else:
                merged_url = ledger_entry.get("pr_url") or f"https://github.com/{full_repo_name}/tree/{req.branch_name}"
            summary = (f"Already merged (PR ledger, merged by {ledger_entry.get('merged_by') or 'StackVend'}) "
                       f"{_review_location(merged_url, req.branch_name)}")
            agent.set_summary(summary, status="SUCCESS")
            _record_release_stage_merged(db, trace_id, summary)
            return {"status": "SUCCESS", "product_id": req.product_id, "branch_name": req.branch_name,
                    "approval_id": "", "auto_merged": True, "already_merged": True,
                    "require_human_code_review": None, "pull_request_url": merged_url, "summary": summary,
                    "decision": None, "release_certificate": ""}

        # Auto-merge only when the workload explicitly opted out of human review (exact bool, RT F7: the derived
        # `auto_merge` display field is never read for a decision) and the request did not ask for review.
        require_review = not (wdata.get("require_human_code_review") is False)
        if req.require_human_code_review is True:
            require_review = True
        # RT F1 (row 23 condition H6) -> SERVERLESS-AUTOMERGE-SHA: a Serverless Git release auto-merges only when the
        # git server confirms it refuses a source branch that moved after QA (expected_source_sha); an older or
        # unreachable git server keeps the human approval. The cause is a typed code + plain text, never "policy".
        serverless_hitl_code: Optional[str] = None
        serverless_hitl_reason: Optional[str] = None
        if vcs_provider == vcs_ledger.PROVIDER_SERVERLESS_GIT and not require_review:
            serverless_hitl_code, serverless_hitl_reason = _serverless_source_check_gap(req.product_id, full_repo_name)
            if serverless_hitl_code is not None:
                require_review = True
        # ---- FD-4P / FD-4BB end ----

        # Stage 3: Lead Release Gatekeeper evaluation
        # ---- FD-4F (RL-1..3, D7, D10) begin: QA evidence must exist, match this run, and be bound to the head ----
        qa_data: Dict[str, Any] = {}
        evidence_reasons: List[str] = []
        if db:
            try:
                qa_doc = db.collection("qa_test_runs").document(trace_id).get()
                if qa_doc.exists:
                    qa_data = qa_doc.to_dict() or {}
            except Exception as q_err:
                evidence_reasons.append(f"QA evidence unreadable ({type(q_err).__name__})")
        else:
            evidence_reasons.append("QA evidence store unavailable")
        evidence_reasons.extend(_qa_evidence_problems(qa_data, req, trace_id, source_backend_factory))
        if qa_data and qa_data.get("commit_sha") != ledger_entry.get("head_sha"):
            logger.error(f"Release: QA-tested {qa_data.get('commit_sha')} is not the StackVend-pushed "
                         f"{ledger_entry.get('head_sha')} on '{req.branch_name}'", extra={"security_event": "branch_moved"})
            evidence_reasons.append("QA evidence is not for the commit StackVend pushed (branch moved after StackVend push)")
        evidence_ok = not evidence_reasons

        if evidence_ok:
            determ_report = qa_data
            sec_report = qa_data.get("security_lens") or {"passed": False}
            adh_report = qa_data.get("adherence_lens") or {"passed": False, "instruction_adherence_score": 0.0, "grounding_score": 0.0}
        else:
            logger.warning(f"Release '{req.product_id}' has no usable QA evidence: {evidence_reasons}")
            determ_report = {"passed": False, "summary": "No usable QA evidence: " + "; ".join(evidence_reasons)}
            sec_report = {"passed": False}
            adh_report = {"passed": False, "instruction_adherence_score": 0.0, "grounding_score": 0.0}

        gate_decision = evaluate_release_decision(
            determ_report=determ_report,
            sec_report=sec_report,
            adh_report=adh_report,
            workload_policy={"require_human_code_review": require_review},
            product_id=req.product_id,
            branch_name=req.branch_name,
        )
        if evidence_reasons:
            gate_decision.blocking_reasons = list(evidence_reasons) + list(gate_decision.blocking_reasons)
        if serverless_hitl_reason:
            gate_decision.blocking_reasons = [serverless_hitl_reason] + list(gate_decision.blocking_reasons)
        # Gatekeeper rejection, missing evidence or HITL requirement overrides auto-merge
        if not gate_decision.is_approved or not evidence_ok:
            require_review = True
        # ---- FD-4F end ----

        merged = False
        ledger_pr_number = ledger_entry.get("pr_number") if vcs_provider == vcs_ledger.PROVIDER_GITHUB else None
        if vcs_provider == "SERVERLESS_GIT":
            # install-polish: neither the Control Center nor the git server has a page that shows a Serverless Git
            # branch to a browser (the git server's tree/blob API needs a service identity), so there is no link:
            # the card names the branch in plain text instead (the old "/workloads/<id>?tab=vcs" path had no route).
            pr_url = ""
        elif isinstance(ledger_entry.get("pr_url"), str) and ledger_entry.get("pr_url"):
            pr_url = ledger_entry["pr_url"]  # pr.html_url from the PR-creation response
        else:
            pr_url = f"https://github.com/{full_repo_name}/tree/{req.branch_name}"

        created_approval_id = None
        merge_failure = None
        main_moved = None
        unchecked_merge = None
        if not require_review and gate_decision is not None and gate_decision.is_approved and evidence_ok:
            try:
                _release_merge(vcs_provider, ledger_entry, req.product_id,
                               f"feat({req.product_id}): automated release merge into {ledger_entry.get('base_branch')} by StackVend")
                merged = True
                logger.info(f"Auto-merged ledger PR for product '{req.product_id}' ({req.branch_name})")
            except MainMovedError as mm_err:  # FD-4BE: typed MAIN_MOVED, never an approval card / 24 h wait
                main_moved, merge_failure = mm_err, str(mm_err)
            except SourceCheckUnconfirmedError as uc_err:  # SERVERLESS-AUTOMERGE-SHA: merged, check not confirmed
                unchecked_merge = uc_err
            except (PRIdentityMismatch, PRMergeNotCompleted) as m_err:
                # Includes ServerlessGitSourceMoved (git server 409 SOURCE_MOVED): GitHub's moved-head path.
                merge_failure = str(m_err)
            except Exception as m_err:  # noqa: BLE001 - provider/transport error: a human decides on the card
                merge_failure = f"{type(m_err).__name__}: {m_err}"
            try:
                if merged:
                    # RT F1: a Serverless Git merge only reaches here with the check confirmed; GitHub: no field.
                    confirmed = ({"source_check_confirmed": True}
                                 if vcs_provider == vcs_ledger.PROVIDER_SERVERLESS_GIT else {})
                    vcs_ledger.mark(db, ledger_entry["ledger_id"], vcs_ledger.STATE_MERGED, merged_by="release-gatekeeper",
                                    **confirmed)
                elif unchecked_merge is not None:
                    # The server reported the merge as done: the ledger says so, typed, with why the run stops.
                    vcs_ledger.mark(db, ledger_entry["ledger_id"], vcs_ledger.STATE_MERGED, merged_by="release-gatekeeper",
                                    reason=f"SOURCE_CHECK_UNCONFIRMED: {unchecked_merge}", source_check_confirmed=False)
                else:
                    vcs_ledger.mark(db, ledger_entry["ledger_id"], vcs_ledger.STATE_MERGE_FAILED, reason=merge_failure)
            except vcs_ledger.LedgerError as l_err:
                logger.critical(f"PR ledger state not recorded for {req.branch_name}: {l_err}")
            if main_moved is not None:
                raise main_moved
            if unchecked_merge is not None:
                logger.critical(f"Release '{req.product_id}' ({req.branch_name}): {unchecked_merge}")
                raise unchecked_merge
            if not merged:
                logger.error(f"Auto-merge refused/failed for '{req.product_id}' ({req.branch_name}): {merge_failure}")
                gate_decision.blocking_reasons = [f"Auto-merge refused: {merge_failure}"] + list(gate_decision.blocking_reasons)
        if not merged:
            action_desc = _release_hitl_action(gate_decision, serverless_hitl_reason)
            logger.info(f"Release of workload '{req.product_id}' needs a human decision ({action_desc}). Left the change open "
                        f"{_review_location(pr_url, req.branch_name)}")
            if db:
                # RT S1: no pending approval for a release that has answered (or whose run ended); one document write
                stage_deadline.guard_side_effect("release.approval", reserve_s=0)
                try:
                    import uuid
                    from datetime import datetime, timezone
                    created_approval_id = f"appr-{req.product_id}-{uuid.uuid4().hex[:6]}"
                    if pr_url:
                        risk_desc = f"Pull Request awaiting human review at {pr_url}. {action_desc}."
                    else:
                        base = ledger_entry.get("base_branch") or "main"
                        risk_desc = (f"Release awaiting human review {_review_location(pr_url, req.branch_name)} "
                                     f"(no pull request page; approving here merges it into {base}). {action_desc}.")
                    # A reason that is already the card's action text (the Serverless Git rule) is not repeated.
                    other_reasons = [r for r in (gate_decision.blocking_reasons if gate_decision else [])
                                     if r != action_desc]
                    if other_reasons:
                        risk_desc += f" Blocking reasons: {'; '.join(other_reasons[:3])}"
                    # FD-4BB: the CC merges an approval only through this ledger entry (and re-checks the live PR).
                    db.collection("approval_requests").document(created_approval_id).set({
                        "approval_id": created_approval_id,
                        "product_id": req.product_id,
                        "trace_id": trace_id,
                        "github_repo": full_repo_name,
                        "cost_delta_monthly": "$0.00/mo",
                        "risk_assessment": risk_desc,
                        "status": "PENDING",
                        "requested_at": datetime.now(timezone.utc).isoformat(),
                        "pull_request_url": pr_url,
                        "branch_name": req.branch_name,
                        "pr_number": ledger_pr_number,
                        "ledger_id": ledger_entry["ledger_id"],
                        "head_sha": ledger_entry.get("head_sha"),
                        "vcs_provider": vcs_provider,
                        "hitl_reason_code": serverless_hitl_code,
                        "release_decision": gate_decision.model_dump() if gate_decision else None,
                        "release_certificate": gate_decision.release_certificate_markdown if gate_decision else "",
                    }, merge=True)
                    logger.info(f"Created pending HITL approval request '{created_approval_id}' in Firestore for '{req.product_id}'")
                except Exception as app_err:
                    # RT H1/N25: never answer 200 with an empty approval_id (the old callback fan-out trigger).
                    raise GateUnavailableError(f"release: approval record not written ({type(app_err).__name__})",
                                               reason="APPROVAL_WRITE_FAILED", stage="release") from app_err

        # Persist Release Certificate in Firestore for universal visibility
        if db and gate_decision:
            try:
                db.collection("pipeline_executions").document(trace_id).set({
                    "release_decision": gate_decision.model_dump(),
                    "release_certificate": gate_decision.release_certificate_markdown,
                }, merge=True)
                db.collection("workloads").document(req.product_id).collection("release_certificates").document(trace_id).set(
                    gate_decision.model_dump(), merge=True
                )
            except Exception as rc_err:
                logger.warning(f"Could not persist release_certificate to Firestore: {rc_err}")

        # Post PR Certificate comment via VCSProvider
        if gate_decision and post_release_certificate_to_vcs is not None:
            stage_deadline.guard_side_effect("release.certificate_comment", reserve_s=0)   # RT S1 (outside the try)
            try:
                post_release_certificate_to_vcs(
                    full_repo_name=full_repo_name,
                    pr_number=ledger_pr_number,  # FD-4P (S14): from the ledger, never parsed from a URL
                    markdown_content=gate_decision.release_certificate_markdown,
                    product_id=req.product_id,
                    project_id=project_id,
                    default_owner=os.getenv("GITHUB_OWNER", ""),
                    vcs_provider_name=vcs_provider,
                )
            except Exception as vcs_comment_err:
                logger.debug(f"Could not post PR certificate comment: {vcs_comment_err}")

        where = _review_location(pr_url, req.branch_name)
        summary = (f"Auto-merged into main {where}" if merged
                   else f"{'Pull Request' if pr_url else 'Release'} awaiting human code review {where}")
        agent.set_summary(summary, status="SUCCESS" if (merged or created_approval_id) else "FAILED")
        if merged:
            _record_release_stage_merged(db, trace_id, _merged_stage_summary("Auto-merged", ledger_entry, where))

        return {
            "status": "SUCCESS" if (merged or created_approval_id) else "FAILED",
            "product_id": req.product_id,
            "branch_name": req.branch_name,
            "approval_id": created_approval_id or "",
            "auto_merged": merged,
            "require_human_code_review": require_review,
            "hitl_reason_code": None if merged else serverless_hitl_code,
            "pull_request_url": pr_url,
            "summary": summary,
            "decision": gate_decision.model_dump() if gate_decision else None,
            "release_certificate": gate_decision.release_certificate_markdown if gate_decision else "",
        }


def _review_location(pr_url: str, branch_name: str) -> str:
    """Where a person reviews a release: the pull request URL, or (Serverless Git, no browsable page) the branch."""
    if pr_url:
        return f"at {pr_url}"
    return f"on branch {branch_name} in the StackVend git server"


def _approval_callback_problems(record: Dict[str, Any], req: "ApprovalCallbackRegistration") -> List[str]:
    problems = []
    if record.get("product_id") != req.product_id:
        problems.append("PRODUCT_MISMATCH")
    if req.trace_id is not None and record.get("trace_id") != req.trace_id:
        problems.append("TRACE_MISMATCH")
    if record.get("status") != "PENDING":
        problems.append("NOT_PENDING")
    return problems


def _register_callback_checked(ref: Any, req: "ApprovalCallbackRegistration") -> None:
    """Check the record and set callback_url as ONE atomic step (bundle RT F7, plan §4.5 AJ-7).

    Real Firestore (an instance of google.cloud.firestore_v1 DocumentReference): a read-check-write TRANSACTION, so
    a decision the Control Center writes between the read and the write aborts the commit, the library re-runs the
    check, and the now-decided record answers 409 NOT_PENDING instead of taking a callback_url. Plain in-memory fakes
    (unit tests only) use the same check without a transaction; production always runs on the real client (same
    dispatch as apps/control-center/routes/approvals.py::_cas_claim). Raises HTTPException 404 / ContractViolationError
    409; store errors propagate to the caller (-> 503)."""
    def _check(snap) -> None:
        if not snap.exists:
            raise HTTPException(status_code=404, detail={
                "error_class": "CONTRACT_VIOLATION", "reason": "APPROVAL_NOT_FOUND", "stage": "release",
                "summary": f"approval {req.approval_id} not found"})
        problems = _approval_callback_problems(snap.to_dict() or {}, req)
        if problems:
            raise ContractViolationError(f"approval {req.approval_id} cannot take this callback: {', '.join(problems)}",
                                         reason=problems[0], stage="release", details={"problems": problems})

    try:
        from google.cloud.firestore_v1.document import DocumentReference as _FirestoreDocRef
    except ImportError:  # pragma: no cover - the gateway image always ships google-cloud-firestore
        _FirestoreDocRef = None
    if _FirestoreDocRef is not None and isinstance(ref, _FirestoreDocRef):
        from google.cloud.firestore_v1 import transactional

        @transactional
        def _txn(txn):
            _check(ref.get(transaction=txn))
            txn.update(ref, {"callback_url": req.callback_url})

        _txn(ref._client.transaction())
        return
    _check(ref.get())
    ref.set({"callback_url": req.callback_url}, merge=True)


@app.post("/events/approval-callback")
def register_approval_callback(req: ApprovalCallbackRegistration, gdb: Any = Depends(get_governance_db)):
    """
    Invoked by the main_orchestrator workflow to register the Cloud Workflows callback URL on exactly ONE pending
    approval_requests record (lane 17 AJ-7): the record must exist (404), belong to this product and trace and still
    be PENDING (409). Firestore unavailable -> 503. The old "no id -> every pending record of the product" fan-out
    is gone. Bundle RT F7: check + write run in one Firestore transaction, so a decision landing in between can no
    longer leave a callback_url on a decided record.
    """
    if gdb is None:
        raise GateUnavailableError("approval store unavailable", reason="STORE_UNAVAILABLE", stage="release")
    ref = gdb.collection("approval_requests").document(req.approval_id)
    try:
        _register_callback_checked(ref, req)
    except (HTTPException, GateError):
        raise
    except Exception as e:
        raise GateUnavailableError(f"approval store unavailable ({type(e).__name__})", reason="STORE_UNAVAILABLE",
                                   stage="release") from e
    logger.info(f"Registered approval callback on approval '{req.approval_id}'")
    return {"status": "SUCCESS", "approval_id": req.approval_id}


@app.post("/events/plan-approval-request")
def register_plan_approval_request(req: PlanApprovalRequest):
    """
    Invoked by Step 2.5 of castor_main_orchestrator workflow to register an Architectural
    Plan approval gate with callback URL before repository and project vending.
    """
    import uuid
    import time
    project_id = os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT") or ""
    approval_id = f"plan-{req.product_id}-{uuid.uuid4().hex[:6]}"
    try:
        from google.cloud import firestore
        fs_db = db or (firestore.Client(project=project_id) if project_id else firestore.Client())
        if fs_db:
            record = {
                "approval_id": approval_id,
                "approval_type": "ARCHITECTURAL_PLAN",
                "product_id": req.product_id,
                "trace_id": req.trace_id,
                "status": "PENDING",
                "callback_url": req.callback_url,
                "plan_markdown": req.plan_markdown,
                "plan_file_path": req.plan_file_path,
                "task_dag": req.task_dag,
                "cost_delta_monthly": req.cost_delta_monthly,
                "compliance_summary": req.compliance_summary,
                "rework_cycle": req.rework_cycle or 0,
                "created_at": time.time(),
                "created_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "requested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            fs_db.collection("approval_requests").document(approval_id).set(record)
            if req.trace_id:
                fs_db.collection("pipeline_executions").document(req.trace_id).set({
                    "state": "AWAITING_PLAN_APPROVAL",
                    "current_step": "AWAITING_PLAN_APPROVAL",
                    "approval_id": approval_id,
                    "updated_at": time.time(),
                }, merge=True)
            logger.info(f"Registered plan approval request '{approval_id}' for '{req.product_id}'")
        return {
            "status": "SUCCESS",
            "approval_id": approval_id,
            "product_id": req.product_id,
            "requires_human_approval": True,
        }
    except Exception as e:
        # Lane 17 (FD-4AG): an approval that was not recorded must stop the run, never look like a 200.
        logger.error(f"Failed to register plan approval request: {e}", exc_info=True)
        raise GateUnavailableError(f"plan approval request not recorded ({type(e).__name__})",
                                   reason="APPROVAL_NOT_RECORDED", stage="plan_approval") from e


class ServiceUrlUnavailable(GateUnavailableError):
    """FALLBACK-URLS (fail-loudly 1.4): a platform service's URL is not known from a typed source (its env override
    or the Cloud Run Admin API). Never replaced by a made-up `https://<svc>-<hash>.a.run.app`, `http://<svc>:8080`
    or a default region. 503 GATE_UNAVAILABLE, reason SERVICE_URL_UNKNOWN, details.service = the service name."""


# SAT-13 (b) URL cache: the Cloud Run Admin API answer is reused for this many seconds, so a validate or dispatch does
# not call the API every time for the same platform service. Owner-confirmable constant (OQ-16 recommendation: 10
# minutes). Only an Admin-API `https://` uri is cached, keyed by (project, region, service); an env override is never
# cached (it is read on every call) and a failed or empty lookup is never cached (the next call asks the API again).
import threading as _threading  # noqa: E402  (kept in this region: SAT-13)

SERVICE_URL_CACHE_TTL_S = 600.0
_SERVICE_URL_CACHE: Dict[Tuple[str, str, str], Tuple[str, float]] = {}  # key -> (url, expires_at on the clock below)
_SERVICE_URL_CACHE_LOCK = _threading.Lock()
_service_url_clock = time.monotonic  # tests replace it with a fake clock


def _cached_service_url(key: Tuple[str, str, str]) -> Optional[str]:
    with _SERVICE_URL_CACHE_LOCK:
        hit = _SERVICE_URL_CACHE.get(key)
        if hit is None:
            return None
        if _service_url_clock() < hit[1]:
            return hit[0]
        del _SERVICE_URL_CACHE[key]  # expired: the caller asks the API again
        return None


def _remember_service_url(key: Tuple[str, str, str], url: str) -> None:
    with _SERVICE_URL_CACHE_LOCK:
        _SERVICE_URL_CACHE[key] = (url, _service_url_clock() + SERVICE_URL_CACHE_TTL_S)


def resolve_service_url(service_name: str) -> str:
    """The live URL of a platform Cloud Run service, from a typed source only:
    1. its environment override (e.g. GATEWAY_URL, INFRACOST_MCP_URL), when set (never cached);
    2. the Cloud Run Admin API (`run_v2.ServicesClient.get_service`) in PROJECT_ID / REGION (the platform Terraform
       sets REGION on the gateway; no region default, invariant 3) -> the service's `uri`. A returned `https://` uri
       is kept for SERVICE_URL_CACHE_TTL_S per (project, region, service) (SAT-13); failures are never cached.
    Otherwise raises ServiceUrlUnavailable (FALLBACK-URLS: the old deterministic-hash and `http://<svc>:8080` guesses
    are gone; a URL nobody serves is never handed to the workflow or a client)."""
    env_map = {
        "orchestrator-gateway-service": "GATEWAY_URL",
        "project-repo-vending-service": "VENDING_MCP_URL",
        "mcp-workspace-connector": "WORKSPACE_MCP_URL",
        "mcp-terraform-server": "TERRAFORM_MCP_URL",
        "mcp-infracost-server": "INFRACOST_MCP_URL",
        "mcp-github-toolserver": "GITHUB_MCP_URL",
        "mcp-kubernetes-server": "KUBERNETES_MCP_URL",
        "mcp-compliance-server": "COMPLIANCE_SERVER_URL",
    }
    env_var = env_map.get(service_name)
    if env_var and os.getenv(env_var):
        return os.getenv(env_var).rstrip("/")

    project_id = (os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT") or "").strip()
    region = (os.getenv("REGION") or "").strip()
    if not (project_id and region):
        raise ServiceUrlUnavailable(
            f"URL of '{service_name}' unknown: {env_var or 'no env override'} unset and PROJECT_ID/REGION not "
            f"configured for the Cloud Run Admin API lookup",
            reason="SERVICE_URL_UNKNOWN", stage="service_discovery",
            details={"service": service_name, "lookup": "NOT_CONFIGURED"})
    cache_key = (project_id, region, service_name)
    cached = _cached_service_url(cache_key)
    if cached is not None:
        return cached
    try:
        from google.cloud import run_v2
        client = run_v2.ServicesClient()
        svc_obj = client.get_service(name=client.service_path(project_id, region, service_name))
    except Exception as e:  # noqa: BLE001 - classified by type below, never by message
        raise ServiceUrlUnavailable(
            f"URL of '{service_name}' unknown: Cloud Run Admin API lookup failed ({type(e).__name__})",
            reason="SERVICE_URL_UNKNOWN", stage="service_discovery",
            details={"service": service_name, "lookup": "FAILED", "error_type": type(e).__name__}) from e
    uri = getattr(svc_obj, "uri", None)
    if isinstance(uri, str) and uri.startswith("https://"):
        url = uri.rstrip("/")
        _remember_service_url(cache_key, url)
        return url
    raise ServiceUrlUnavailable(
        f"URL of '{service_name}' unknown: the Cloud Run service reports no https uri",
        reason="SERVICE_URL_UNKNOWN", stage="service_discovery",
        details={"service": service_name, "lookup": "NO_URI"})


REFACTOR_INTAKE_COLLECTION = "refactor_intake_requests"
REFACTOR_INTAKE_WINDOW_S = 7 * 24 * 3600


def _autonomous_intake_suppression(fs_client: Any, channel: str, payload: Dict[str, Any]) -> Optional[str]:
    """Lane 14 PR-4: SUPPRESSED:<reason> for an autonomous event the ledger does not allow, else None. Firestore
    errors raise 503 (Pub/Sub retries), never a dispatch."""
    product_id = payload["product_id"]
    try:
        snap = fs_client.collection("workloads").document(product_id).get()
        workload = (snap.to_dict() or {}) if snap.exists else None
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"workload ledger unreadable ({type(e).__name__})")
    refusal = _intake_policy.autonomous_ledger_refusal(channel, workload)
    if refusal or channel != _intake_policy.CHANNEL_REFACTOR:
        return refusal
    # RT F11: one request per (product, findings digest) for 7 days, made atomic. validate_intake guarantees the digest.
    # `create()` is the atomic claim (two deliveries with different traces cannot both open it); an expired claim is
    # re-opened only with a precondition on the version that was read (a concurrent re-open fails -> 503 -> retry).
    from google.api_core import exceptions as gexc

    digest = payload["findings_digest"]
    ref = fs_client.collection(REFACTOR_INTAKE_COLLECTION).document(f"{product_id}--{digest}")
    now = time.time()
    claim = {"product_id": product_id, "findings_digest": digest, "trace_id": payload.get("trace_id"),
             "scan_id": payload.get("scan_id"), "opened_at": now}
    try:
        try:
            ref.create(claim)
            return None
        except gexc.AlreadyExists:
            pass
        prior_snap = ref.get()
        prior = (prior_snap.to_dict() or {}) if prior_snap.exists else {}
        if prior.get("trace_id") == payload.get("trace_id"):
            return None  # a redelivery of the message that opened the request: go on
        if now - float(prior.get("opened_at") or 0) < REFACTOR_INTAKE_WINDOW_S:
            return "SUPPRESSED:DUPLICATE_OPEN_REQUEST"
        ref.update(claim, option=fs_client.write_option(last_update_time=prior_snap.update_time))
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"refactor request ledger unavailable ({type(e).__name__})")
    return None


def _maintenance_refusal(action: str) -> Optional[Dict[str, Any]]:
    """settings-toggles: shared.settings.new_run_refusal (strict read); no settings module -> refused."""
    try:
        from shared.settings import new_run_refusal
    except ImportError as imp_err:
        return {"code": "PLATFORM_SETTINGS_UNAVAILABLE", "errors": [],
                "message": f"Platform settings module unavailable ({imp_err}): {action} was refused."}
    return new_run_refusal(action, project_id=os.getenv("PROJECT_ID") or None)


def _compliance_advisories_block() -> bool:
    """settings-toggles: shared.settings.compliance_advisories_block (strict read); no settings module -> True."""
    try:
        from shared.settings import compliance_advisories_block
    except ImportError:
        return True
    return compliance_advisories_block(project_id=os.getenv("PROJECT_ID") or None)


def _drive_verified_submitter(fs: Any, trace_id: Any, product_id: str) -> Optional[str]:
    """OSS-D23 (owner 10-20): the Drive file owner the spec-ingestion poller recorded from Drive API metadata
    (``intake_submitters/{trace_id}``, written only by the poller), as ``user:<email>``; None when there is no such
    record, it names another product or another verification, or the address is not a listable user
    (``verified_submitter_member``). The identity is never read from the event body itself. Unreadable ->
    GateUnavailableError (503)."""
    from shared.access_policy import verified_submitter_member

    return verified_submitter_member(_drive_verified_submitter_email(fs, trace_id, product_id))


def _drive_verified_submitter_email(fs: Any, trace_id: Any, product_id: str) -> Optional[str]:
    """The address of ``_drive_verified_submitter`` as the poller recorded it (None in every case that lists nobody):
    RT14 D3 keys the submitter's Control Center user record by it, exactly as the poller's submitter check does."""
    from shared.access_policy import verified_submitter_member

    if not isinstance(trace_id, str) or not trace_id:
        return None
    try:
        ref = fs.collection("intake_submitters").document(trace_id)
    except ValueError:  # RT F4: not a valid document id (e.g. contains '/'): no listable record -> nobody listed
        return None
    try:
        snap = ref.get()
        data = (snap.to_dict() or {}) if snap.exists else {}
    except Exception as e:  # noqa: BLE001
        raise GateUnavailableError(f"intake submitter record unreadable ({type(e).__name__})",
                                   reason="ACCESS_DEFAULT_UNAVAILABLE", details={"product_id": product_id}) from e
    if not isinstance(data, dict) or data.get("product_id") != product_id or data.get("verified_by") != "drive_file_owner":
        return None
    email = data.get("email")
    return email if verified_submitter_member(email) is not None else None


# RT14 D3 (owner 11-14): the Control Center user store and access audit (apps/control-center/routes/users.py) and the
# roles whose Drive submitter is assigned to the NEW workload its spec created (ADMIN already has every workload; the
# legacy APPROVER is a Workload Manager, users.py _stored_role). Only these exact values; nothing else is assigned.
CC_USER_COLLECTION = "authorized_users"
CC_USER_ACCESS_AUDIT_COLLECTION = "user_access_audit"
DRIVE_SUBMITTER_ASSIGNED_ROLES = frozenset({"WORKLOAD_MANAGER", "APPROVER"})
DRIVE_SUBMITTER_ASSIGNMENT_ACTION = "USER_ACCESS_AUTO_ASSIGNED"
DRIVE_SUBMITTER_ASSIGNMENT_OPERATOR = "spec-ingestion (Drive file owner)"


def _drive_submitter_manager(fs: Any, email: Optional[str], product_id: str) -> Optional[Tuple[Any, Any, Dict[str, Any], str]]:
    """RT14 D3: (user ref, its read snapshot, its record, its key) when the Drive-verified submitter of a NEW workload
    (no ``workloads/{product_id}`` document) is to be assigned to it as its Workload Manager, else None (an existing
    workload is never read further and never changes). The record is ``authorized_users/{email}`` keyed exactly as
    the poller's submitter check keys it (the address stripped, ASCII only, lower-cased); it must be ACTIVE
    (``is_active`` missing or exactly True) with a role in DRIVE_SUBMITTER_ASSIGNED_ROLES (default APPROVER, as the
    poller reads it) and not already list the workload. Unreadable -> GateUnavailableError (503, Pub/Sub retries;
    nothing created)."""
    if not isinstance(email, str) or not email.strip() or not email.strip().isascii():
        return None
    key = email.strip().lower()
    try:
        ref = fs.collection(CC_USER_COLLECTION).document(key)
    except ValueError:  # not a valid document id: cannot be a Control Center user
        return None
    try:
        if fs.collection("workloads").document(product_id).get().exists:
            return None
        snap = ref.get()
        data = (snap.to_dict() or {}) if snap.exists else None
    except Exception as e:  # noqa: BLE001
        raise GateUnavailableError(f"workload or submitter user record unreadable ({type(e).__name__})",
                                   reason="ACCESS_DEFAULT_UNAVAILABLE", details={"product_id": product_id}) from e
    if not isinstance(data, dict) or data.get("is_active", True) is not True:
        return None
    if data.get("role", "APPROVER") not in DRIVE_SUBMITTER_ASSIGNED_ROLES:
        return None
    assigned = data.get("assigned_workloads")
    assigned = list(assigned) if isinstance(assigned, (list, tuple)) else []
    if product_id in {p.strip().lower() for p in assigned if isinstance(p, str)}:
        return None  # already assigned (an administrator listed it first): nothing to change
    return ref, snap, data, key


def _user_access_view(data: Dict[str, Any]) -> Dict[str, Any]:
    """The access fields of a user record as the Control Center audit stores them (users.py ``_access_view``)."""
    workloads = data.get("assigned_workloads")
    return {"role": data.get("role"), "is_active": data.get("is_active", True),
            "assigned_workloads": list(workloads) if isinstance(workloads, (list, tuple)) else []}


def _freeze_new_workloads_setting() -> bool:
    """FD-4CU: governance.freeze_new_workloads for a workload document seeded here (strict read, 60 s cache). True
    unless the setting is exactly False; True (frozen) when the settings or the reader cannot be loaded. Never raises:
    the seed never fails because of this read."""
    try:
        from shared.settings import freeze_new_workloads_enabled
    except Exception as e:  # noqa: BLE001
        logger.warning(f"governance.freeze_new_workloads reader unavailable ({type(e).__name__}: {e}); "
                       "the new workload starts frozen.")
        return True
    try:
        return freeze_new_workloads_enabled(project_id=os.getenv("PROJECT_ID") or None)
    except Exception as e:  # noqa: BLE001 - the reader never raises; belt and braces
        logger.warning(f"governance.freeze_new_workloads could not be read ({type(e).__name__}: {e}); "
                       "the new workload starts frozen.")
        return True


def _new_workload_branch_setting() -> str:
    """FD-4CI-b-R1: orchestration.default_branch for a workload document seeded here (strict read, 60 s cache); "main"
    -- the branch such a workload used before -- when the settings or the reader cannot be loaded or the value is not a
    plain branch name. Never raises: the seed never fails because of this read."""
    try:
        from shared.settings import default_branch_setting
    except Exception as e:  # noqa: BLE001
        logger.warning(f"orchestration.default_branch reader unavailable ({type(e).__name__}: {e}); using main.")
        return "main"
    try:
        return default_branch_setting(project_id=os.getenv("PROJECT_ID") or None)
    except Exception as e:  # noqa: BLE001 - the reader never raises; belt and braces
        logger.warning(f"orchestration.default_branch could not be read ({type(e).__name__}: {e}); using main.")
        return "main"


def _seed_platform_default_access(fs: Any, product_id: str, submitter_member: Optional[str] = None,
                                  verified_by: Optional[str] = None,
                                  manager: Optional[Tuple[Any, Any, Dict[str, Any], str]] = None) -> Optional[str]:
    """OSS-D23 (owner 10-19/10-20): a NEW workload that arrives by an intake channel (Drive, ...) with no workload
    document gets the platform default access record (``shared.access_policy.platform_default_access_record``:
    PRIVATE_IAP, listing only a platform-verified submitter, else nobody) before dispatch, so it is never public by
    omission; with nobody listed its build stops with ACCESS_POLICY_INCOMPLETE until an administrator lists who may
    use it. ``create()`` writes only when the document does not exist (AlreadyExists -> False): an existing workload
    keeps whatever it has (no silent migration). Any other failure raises GateUnavailableError (the intake answers
    503 and Pub/Sub retries), never a public default.

    FD-4CU: the seeded document is the workload's first record, so it also carries the initial ``code_freeze`` from
    governance.freeze_new_workloads (default on; unreadable -> frozen), written atomically with the access record.
    Project vending later keeps that value (it never overwrites an existing code_freeze).

    FD-4CI-b-R1: it also carries the workload's ``default_branch`` (Settings > Default GitHub Branch, else main), which
    vending creates the repository with and every later stage reads. Returns the seeded branch name when the document
    was created, None when it already existed (an existing workload keeps its recorded branch).

    RT14 D3 (owner 11-14): ``manager`` (``_drive_submitter_manager``) assigns the Drive submitter to the workload in the
    same atomic batch as the create (their Control Center record gains the id in ``assigned_workloads``, with a
    ``user_access_audit`` entry), so the workload exists only with its manager assigned. The user update carries a
    precondition on the version read: a concurrent administrator change fails the batch (503, Pub/Sub retries and
    re-reads) instead of being overwritten. An existing workload: AlreadyExists, nothing assigned."""
    from google.api_core import exceptions as gexc
    from shared.access_policy import (PLATFORM_DEFAULT_ACCESS_SOURCE, SUBMITTER_PROVENANCE_FIELD,
                                      platform_default_access_record, submitter_provenance)

    now_iso = datetime.now(timezone.utc).isoformat()
    doc = {
        "product_id": product_id,
        "access": platform_default_access_record(submitter_member),
        "access_updated_at": now_iso,
        "access_updated_by": PLATFORM_DEFAULT_ACCESS_SOURCE,
        "code_freeze": _freeze_new_workloads_setting(),
        "default_branch": _new_workload_branch_setting(),
    }
    if submitter_member is not None:
        doc[SUBMITTER_PROVENANCE_FIELD] = submitter_provenance(submitter_member, verified_by)
    workload_ref = fs.collection("workloads").document(product_id)
    try:
        if manager is None:
            workload_ref.create(doc)
        else:
            user_ref, user_snap, before, user_key = manager
            after = dict(before, assigned_workloads=_user_access_view(before)["assigned_workloads"] + [product_id])
            batch = fs.batch()
            batch.create(workload_ref, doc)
            batch.update(user_ref, {"assigned_workloads": after["assigned_workloads"]},
                         option=fs.write_option(last_update_time=user_snap.update_time))
            batch.set(fs.collection(CC_USER_ACCESS_AUDIT_COLLECTION).document(), {
                "action": DRIVE_SUBMITTER_ASSIGNMENT_ACTION, "email": user_key,
                "operator_email": DRIVE_SUBMITTER_ASSIGNMENT_OPERATOR, "timestamp": now_iso,
                "before": _user_access_view(before), "after": _user_access_view(after), "product_id": product_id})
            batch.commit()
    except gexc.AlreadyExists:
        return None
    except Exception as e:  # noqa: BLE001
        raise GateUnavailableError(f"platform default access record not written ({type(e).__name__})",
                                   reason="ACCESS_DEFAULT_UNAVAILABLE", details={"product_id": product_id}) from e
    logger.info(f"New workload '{product_id}': platform default access record stored (PRIVATE_IAP, "
                f"{'submitter listed' if submitter_member else 'nobody listed'}; branch {doc['default_branch']}"
                f"{'; Drive submitter assigned as its Workload Manager' if manager is not None else ''})")
    return doc["default_branch"]


def _admit_intake_run(fs_client: Any, payload: Dict[str, Any], intake_channel: Any) -> Optional[Dict[str, Any]]:
    """BUILD-ADMISSION-QUEUE (G4): None when the run may start now (a slot is held, or the run needs none: Fast-Path
    DEPLOY_ONLY); else the intake answer of a run that waits in the build queue (acked, nothing dispatched). A store
    that cannot be read or written -> 503, so Pub/Sub retries and never starts an unaccounted run."""
    if not _build_admission.requires_admission(payload):
        return None
    trace_id = payload.get("trace_id")
    product_id = str(payload.get("product_id") or "")
    if not isinstance(trace_id, str) or not trace_id.strip():
        raise HTTPException(status_code=422, detail={"status": "SUPPRESSED:MISSING_TRACE_ID",
                                                     "detail": "an LLM build needs a trace_id to take a build slot"})
    _reconcile_slot_holders(fs_client)   # RT F3a: a holder whose workflow ended without telling anyone frees its slot
    queued_record = _build_admission.queued_run_record(
        trace_id=trace_id, product_id=product_id, title=str(payload.get("title") or f"Build: {product_id}"),
        execution_mode=str(payload.get("execution_mode") or "FULL").upper(), source=str(intake_channel or ""),
        now_iso=datetime.now(timezone.utc).isoformat(), request_id=_intake_policy.run_request_id(payload))
    try:
        admission = _build_admission.admit(
            fs_client, trace_id, product_id=product_id, payload=payload, source=str(intake_channel or ""),
            before_queue=lambda: _build_admission.create_queued_run_record(fs_client, queued_record))
    except _build_admission.BuildAdmissionError as err:
        logger.error(f"{err.error_class}: intake of {trace_id} not admitted: {err.message}")
        raise HTTPException(status_code=503, detail=err.body())
    if admission.state == _build_admission.ADMITTED:
        return None
    if admission.pump_needed:
        _pump_queued_builds(fs_client)
    return {"status": _build_admission.QUEUED, "trace_id": trace_id, "build_queue": admission.view()}


# BUILD-ADMISSION-QUEUE RT F3a: the gateway's admission reads, when every build slot is taken, the Workflows state of
# the holders whose run is still recorded as running, and closes the ones whose workflow has ended (the same rule as
# the Control Center's STALE-RUN-AUTOFAIL-BOUND reconcile, routes/telemetry.py `_reconcile_bound_run`: SUCCEEDED ->
# SUCCEEDED, FAILED -> FAILED, CANCELLED -> ABORTED, HTTP 404 on the stored name -> FAILED; any other read error leaves
# the run as it is). So Drive, refactor and SRE intake free the slot of a dead run without the Control Center open.
# Its service account holds roles/workflows.invoker (the read the Control Center makes); no new IAM.
_HOLDER_STATE_READS_PER_ADMISSION = 3
_HOLDER_STATE_READ_TIMEOUT_SECONDS = 5.0
_RUN_STATUSES_RECONCILED = ("ACTIVE", "RUNNING", "PAUSED_RATE_LIMIT_COOLDOWN")
_WF_TERMINAL_RUN = {
    "SUCCEEDED": ("SUCCEEDED", None, None),
    "FAILED": ("FAILED", "WORKFLOW_EXECUTION_FAILED",
               "Workflow execution ended FAILED; its final status notification was not received, so the run was "
               "closed by the gateway's build admission"),
    "CANCELLED": ("ABORTED", "WORKFLOW_EXECUTION_CANCELLED",
                  "Workflow execution was cancelled; the run was closed by the gateway's build admission"),
}


class _ShortTimeoutSession:
    def __init__(self, inner: Any):
        self._inner = inner

    def get(self, url: str, timeout: Optional[float] = None, **kwargs: Any) -> Any:
        return self._inner.get(url, timeout=_HOLDER_STATE_READ_TIMEOUT_SECONDS, **kwargs)


# RT14-25 (RT item 3): the admission reconcile runs inside a Pub/Sub intake request whose reads are capped at a few
# seconds, so its redelivery makes one short attempt per kept outcome (no backoff); a failed one stays PENDING for the
# next reconcile. The Control Center's bound-run reconcile keeps the default sender.
_ADMISSION_REDELIVERY_TIMEOUT_SECONDS = 5


def _admission_redelivery_send(url: str, payload: Dict[str, Any]) -> Any:
    return CallbackDeliveryClient.send_callback(callback_url=url, payload=payload,
                                                timeout=_ADMISSION_REDELIVERY_TIMEOUT_SECONDS, max_attempts=1)


def _reconcile_slot_holders(fs_client: Any) -> int:
    """Closes the run records of build-slot holders whose workflow execution has ended (Workflows API), so the
    admission that follows frees their slots. Only when every slot is taken; at most
    _HOLDER_STATE_READS_PER_ADMISSION reads. Returns the number closed. Never raises (logged)."""
    try:
        state = _build_admission.read_state(fs_client)
        if len(state["holders"]) < _build_admission.read_limit(fs_client):
            return 0
    except Exception as err:  # noqa: BLE001 - the admission itself reports an unreadable store
        logger.warning(f"Build slot holders not reconciled ({type(err).__name__}: {err})")
        return 0
    project = os.getenv("PROJECT_ID", "")
    region = (os.getenv("REGION") or "").strip()
    session = None
    reads = closed = 0
    now_iso = datetime.now(timezone.utc).isoformat()
    for trace_id in list(state["holders"]):
        try:
            ref = fs_client.collection("pipeline_executions").document(trace_id)
            snap = ref.get()
            record = (snap.to_dict() or {}) if snap.exists else None
            if not record or str(record.get("status") or "").upper() not in _RUN_STATUSES_RECONCILED:
                continue
            name = _wfx.execution_name_of(record, project, region)
            if not name:
                continue
            if reads >= _HOLDER_STATE_READS_PER_ADMISSION:
                break
            reads += 1
            payload = None
            try:
                if session is None:
                    session = _ShortTimeoutSession(_wfx._session())
                wf_state = _wfx.get_execution_state(name, session=session)
            except _wfx.WorkflowExecutionsError as wf_err:
                stored = {v for v in (record.get("workflow_execution_name"), record.get("workflow_execution_id"))
                          if _wfx._is_execution_name(v)}
                if wf_err.http_status != 404 or name not in stored:
                    logger.warning(f"Build slot holder {trace_id}: workflow state not read ({wf_err.code}); left as "
                                   f"it is")
                    continue
                message = (f"Workflow execution {name} was not found (HTTP 404); it no longer exists, so the run was "
                           f"closed by the gateway's build admission")
                payload = {"status": "FAILED", "current_stage": "FAILED", "ended_at": now_iso,
                           "error_class": "WORKFLOW_EXECUTION_NOT_FOUND", "error_message": message}
                if not record.get("error"):
                    payload["error"] = message
            if payload is None:
                if wf_state not in _wfx.TERMINAL_STATES:
                    # RT14-25: the workflow still waits; an outcome that never reached it (a lost tf-applier or
                    # vending callback) is sent again, so the run goes on and frees its slot when it ends.
                    if has_undelivered_stage(record):
                        redeliver_undelivered_callbacks(fs_client, trace_id, send=_admission_redelivery_send)
                    continue
                status_word, error_class, message = _WF_TERMINAL_RUN.get(wf_state, _WF_TERMINAL_RUN["FAILED"])
                payload = {"status": status_word, "current_stage": status_word, "ended_at": now_iso,
                           "workflow_state_check": {"at": now_iso, "outcome": "RECONCILED", "state": wf_state,
                                                    "by": "gateway-build-admission"}}
                if error_class:
                    payload.update(error_class=error_class, error_message=message)
                    if not record.get("error"):
                        payload["error"] = message
            update_time = getattr(snap, "update_time", None)
            if update_time is not None:
                ref.update(payload, option=fs_client.write_option(last_update_time=update_time))
            else:
                ref.set(payload, merge=True)
            closed += 1
            logger.info(f"Build slot holder {trace_id}: its workflow has ended; run closed {payload['status']}")
        except Exception as err:  # noqa: BLE001 - a conflict (a notify landed meanwhile) or a store error: left as is
            logger.warning(f"Build slot holder {trace_id} not reconciled ({type(err).__name__}: {err})")
    return closed


def _build_queue_gate(fs_client: Any) -> Optional[str]:
    """Why queued builds must not be dispatched now (emergency stop, maintenance), else None. Unreadable -> a reason
    (they stay queued; the next terminal event, admission or Control Center poll tries again)."""
    try:
        if _read_kill_switch(fs_client)["active"]:
            return "platform emergency stop is active"
    except GateError as ks_err:
        return ks_err.message
    refusal = _maintenance_refusal("dispatch of a queued build")
    if refusal is not None:
        return str(refusal.get("code") or "maintenance")
    return None


def _dispatch_queued_build(entry: Dict[str, Any]) -> str:
    """Dispatches a queued run through the same intake path as a Pub/Sub delivery (its slot is already held). The
    gateway has no publisher grant on spec-intake-events, so it runs the intake in process."""
    try:
        result = _process_intake(dict(entry["payload"]))
    except HTTPException as http_err:
        detail = f"HTTP {http_err.status_code}: {http_err.detail}"
        if http_err.status_code >= 500:
            # RT F1: the same transient answer that makes Pub/Sub redeliver an admitted event: back to the head of
            # the queue, retried on the next trigger, failed on the 3rd attempt.
            raise _build_admission.BuildDispatchRetryable(detail)
        raise _build_admission.BuildDispatchRefused(_build_admission.BUILD_DISPATCH_REFUSED, detail)
    status_word = str((result or {}).get("status") or "")
    if status_word in ("DISPATCHED", "DUPLICATE"):
        return _build_admission.DISPATCHED
    typed_class = (result or {}).get("error_class")
    if typed_class in (_build_admission.BUILD_QUEUE_WORKLOAD_GONE, RUN_ALREADY_ENDED):   # RT14-14: keep the class
        raise _build_admission.BuildDispatchRefused(typed_class, str((result or {}).get("detail") or status_word))
    raise _build_admission.BuildDispatchRefused(_build_admission.BUILD_DISPATCH_REFUSED,
                                                f"intake answered {status_word or 'nothing'}")


def _pump_queued_builds(fs_client: Any) -> None:
    """Dispatches queued builds into free slots (FIFO). Never raises: a store failure is logged; the next terminal
    event, admission or Control Center poll tries again."""
    try:
        _build_admission.pump(fs_client, _dispatch_queued_build, gate=lambda: _build_queue_gate(fs_client))
    except Exception as err:  # noqa: BLE001
        logger.error(f"{_build_admission.BUILD_ADMISSION_UNAVAILABLE}: queued builds not dispatched now "
                     f"({type(err).__name__}: {err})")


def _verify_intake_request_id(fs_client: Any, payload: Dict[str, Any]) -> None:
    """RESUME-DEVELOPER-TASK-DAG: a `request_id` on an intake event names a feature request of the event's own workload
    (the run's end writes to that document). `IntakeRejected` (422) when it does not; store unreadable -> 503 (Pub/Sub
    retries, then DLQ), never dispatched unchecked. An event with no id reads nothing."""
    request_id = _intake_policy.run_request_id(payload)
    if request_id is None:
        return
    _intake_policy.check_request_id_format(request_id)
    try:
        snap = fs_client.collection("feature_requests").document(request_id).get()
        record = (snap.to_dict() or {}) if snap.exists else None
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"feature request unreadable ({type(e).__name__})") from e
    _intake_policy.check_request_id_owner(payload, request_id, record)


def _refuse_platform_workload_target(fs_client: Any, payload: Dict[str, Any], host_project_id: str) -> None:
    """RT14-02: 422 SUPPRESSED:PLATFORM_WORKLOAD when the event's workload record is the platform workload; 503 when
    the record cannot be read."""
    product_id = payload["product_id"]   # validate_intake guarantees a valid RFC 1123 id
    try:
        snap = fs_client.collection("workloads").document(product_id).get()
        workload = (snap.to_dict() or {}) if snap.exists else None
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"workload ledger unreadable ({type(e).__name__})") from e
    refusal = _intake_policy.platform_workload_refusal(product_id, workload, host_project_id)
    if refusal is not None:
        logger.warning(f"Intake event refused: {refusal.status} ({refusal.detail})")
        raise HTTPException(status_code=refusal.status_code, detail=refusal.body())


@app.post("/events/pubsub-intake")
def handle_pubsub_intake(envelope: PubSubPushEnvelope):
    """
    Receives Pub/Sub push messages from spec-intake-events or autonomous-refactor-events
    and dispatches Cloud Workflows executions.
    """
    try:
        raw_data = base64.b64decode(envelope.message.data).decode("utf-8")
        payload = json.loads(raw_data)
        logger.info(f"Received intake event from Pub/Sub: {payload.get('product_id') if isinstance(payload, dict) else None}")
    except Exception as e:
        logger.error(f"Failed to process Pub/Sub intake message: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    # BUILD-ADMISSION-QUEUE: an event refused for good after the Control Center granted it a build slot frees the slot
    # (typed failure on its run); a 5xx keeps it (Pub/Sub redelivers the event).
    ctx: Dict[str, Any] = {}
    try:
        result = _process_intake(payload, ctx)
    except HTTPException as refused:
        if 400 <= refused.status_code < 500:
            _fail_refused_admitted_run(ctx.get("fs"), payload, f"HTTP {refused.status_code}: {refused.detail}")
        raise
    if isinstance(result, dict) and str(result.get("status") or "").startswith("SUPPRESSED"):
        _fail_refused_admitted_run(ctx.get("fs"), payload, str(result.get("status")))
        if result.get("slot_freed") and ctx.get("fs") is not None:
            _pump_queued_builds(ctx["fs"])   # RT14-14: the refused run's slot went to the next queued build
    return result


def _fail_refused_admitted_run(fs_client: Any, payload: Any, detail: str) -> None:
    """BUILD-ADMISSION-QUEUE: the intake refused an event whose run holds a build slot -> slot freed, run FAILED
    (BUILD_DISPATCH_REFUSED). Nothing happens for a run that holds none, or when the refusal came before the intake had
    a store client (a malformed event: its slot, if any, is freed by the release rule). Never raises (logged)."""
    trace_id = payload.get("trace_id") if isinstance(payload, dict) else None
    if not trace_id or fs_client is None:
        return
    try:
        freed = _build_admission.fail_dispatch(fs_client, str(trace_id), _build_admission.BUILD_DISPATCH_REFUSED,
                                               f"intake refused the run: {detail}")
    except Exception as err:  # noqa: BLE001 - the release rule frees it after the grace period
        logger.error(f"{_build_admission.BUILD_ADMISSION_UNAVAILABLE}: build slot of refused run {trace_id} not "
                     f"released now ({type(err).__name__}: {err}); it is freed after "
                     f"{_build_admission.DISPATCH_GRACE_SECONDS // 60} minutes")
        return
    if freed:
        _pump_queued_builds(fs_client)


# RT14-14: the typed refusal of an intake event whose run already ended (the gateway's other refusal class,
# BUILD_QUEUE_WORKLOAD_GONE, is build_admission's). Run-record statuses that mean the run is over: the same set as
# stage_deadline.RUN_ENDED_STATUSES.
RUN_ALREADY_ENDED = "RUN_ALREADY_ENDED"
_INTAKE_RUN_ENDED_STATUSES = frozenset({"FAILED", "SUCCEEDED", "ABORTED", "CANCELLED", "REJECTED"})


def _refuse_gone_or_ended_run(fs_client: Any, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """RT14-14: None when the event may go on; else its typed refusal (acked: a permanent condition), after freeing the
    build slot or queue place the run holds (build_admission.refuse_run):
    - BUILD_QUEUE_WORKLOAD_GONE: `workloads/{product_id}.status` is DECOMMISSIONED or ARCHIVED (an event delayed past a
      decommission would otherwise run the whole workflow, and vending would create a NEW billed project). A run that
      holds no slot (Fast-Path) has its unbound record failed with the class;
    - RUN_ALREADY_ENDED: `pipeline_executions/{trace_id}.status` already ended (aborted while the event was in flight,
      BUILD_DISPATCH_LOST, a silent run closed). Kept as before: a Fast-Path re-apply the Control Center marked
      DEPLOY_DISPATCH_OUTCOME_UNKNOWN (its publish wait timed out, the message may still arrive) is revived below.
    A read that fails -> 503 (Pub/Sub retries), never dispatched unchecked."""
    trace_id = payload.get("trace_id")
    trace_id = trace_id.strip() if isinstance(trace_id, str) and trace_id.strip() else None
    product_id = payload.get("product_id")
    product_id = product_id.strip() if isinstance(product_id, str) and product_id.strip() else None
    refusal = None
    try:
        if product_id:
            snap = fs_client.collection("workloads").document(product_id).get()
            wl_status = str(((snap.to_dict() or {}) if snap.exists else {}).get("status") or "").upper()
            if wl_status in _build_admission.WORKLOAD_GONE_STATUSES:
                refusal = (_build_admission.BUILD_QUEUE_WORKLOAD_GONE,
                           f"workload '{product_id}' is {wl_status}; the run was not started")
        if refusal is None and trace_id:
            snap = fs_client.collection("pipeline_executions").document(trace_id).get()
            record = (snap.to_dict() or {}) if snap.exists else {}
            run_status = str(record.get("status") or "").upper()
            if (run_status in _INTAKE_RUN_ENDED_STATUSES
                    and record.get("error_class") != DEPLOY_DISPATCH_OUTCOME_UNKNOWN):
                refusal = (RUN_ALREADY_ENDED, f"run {trace_id} already ended ({run_status}); its late intake event "
                                              f"was not started")
    except Exception as read_err:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"workload lifecycle unreadable ({type(read_err).__name__})")
    if refusal is None:
        return None
    error_class, detail = refusal
    logger.warning(f"{error_class}: intake event of '{product_id}' (trace {trace_id}) refused: {detail}")
    freed = False
    if trace_id:
        try:
            freed = _build_admission.refuse_run(
                fs_client, trace_id, error_class, detail,
                fail_unbound_record=error_class == _build_admission.BUILD_QUEUE_WORKLOAD_GONE)
        except _build_admission.BuildAdmissionError as err:
            logger.error(f"{err.error_class}: slot of refused run {trace_id} not freed now: {err.message}")
            raise HTTPException(status_code=503, detail=err.body())
    return {"status": f"SUPPRESSED:{error_class}", "error_class": error_class, "trace_id": trace_id,
            "detail": detail, "slot_freed": freed}


def _process_intake(payload: Any, ctx: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The intake decision for one event (a Pub/Sub delivery, or a queued run the gateway dispatches itself after a run
    ended: BUILD-ADMISSION-QUEUE). Safe to run again for the same trace (designed for Pub/Sub redelivery)."""
    try:
        # Lane 14 PR-4 (row L14-j, lane 17 R17-1): exact source_channel allow-set; an unknown channel or an incomplete
        # autonomous event is 422 (redelivered until the DLQ policy moves it to castor-dlq), never a pipeline.
        try:
            payload = _intake_policy.validate_intake(payload)
        except _intake_policy.IntakeRejected as rejected:
            logger.warning(f"Intake event refused: {rejected.status} ({rejected.detail})")
            raise HTTPException(status_code=rejected.status_code, detail=rejected.body())
        intake_channel = payload.get("source_channel")

        project_id = os.getenv("PROJECT_ID", "")
        region = (os.getenv("REGION") or "").strip()   # FALLBACK-URLS: no region default (invariant 3)
        workflow_name = os.getenv("WORKFLOW_NAME", "castor-main-orchestrator")

        # Lane 17 AJ-11: with no PROJECT_ID nothing can be dispatched; 503 makes Pub/Sub retry and then dead-letter
        # instead of acking a message that never started a pipeline.
        if not project_id:
            raise HTTPException(status_code=503, detail="PROJECT_ID unset: intake cannot dispatch a workflow")
        if not region:
            raise HTTPException(status_code=503, detail="REGION unset: intake cannot dispatch a workflow")

        # Check platform emergency kill switch. Lane 17 AJ-12: unreadable = stop (503 -> Pub/Sub retry -> DLQ).
        try:
            from google.cloud import firestore
            fs_client = firestore.Client(project=project_id)
        except Exception as ks_err:
            raise HTTPException(status_code=503, detail=f"kill switch unreadable ({type(ks_err).__name__})")
        if ctx is not None:
            ctx["fs"] = fs_client   # BUILD-ADMISSION-QUEUE: a later refusal frees an admitted run's slot with it
        try:
            kill_switch = _read_kill_switch(fs_client)
        except GateError as ks_gate:
            raise HTTPException(status_code=503, detail=ks_gate.message)
        if kill_switch["active"]:
            logger.warning(f"Intake event suppressed for '{payload.get('product_id')}': PLATFORM EMERGENCY STOP IS ACTIVE.")
            return {"status": "SUPPRESSED_BY_EMERGENCY_STOP", "message": "Platform emergency stop is active."}

        # Lane 17 AJ-11 dedupe: a redelivery after a successful dispatch must not start a second execution.
        dedupe_trace = payload.get("trace_id")
        if dedupe_trace:
            try:
                prior = fs_client.collection("pipeline_executions").document(dedupe_trace).get()
                prior_exec = ((prior.to_dict() or {}) if prior.exists else {}).get("workflow_execution_id")
            except Exception as dd_err:
                raise HTTPException(status_code=503, detail=f"dedupe check unreadable ({type(dd_err).__name__})")
            if prior_exec:
                logger.info(f"Intake redelivery for trace {dedupe_trace}: execution {prior_exec} already dispatched")
                return {"status": "DUPLICATE", "workflow_execution_id": prior_exec}

        # settings-toggles ST-1 (owner 10-19): maintenance mode starts no new run from any channel. 503 (not an ack):
        # Pub/Sub redelivers (attempts at ~0/10/30/70/150 s), so an event that arrives just before maintenance ends
        # still runs; after the 5th attempt (~2.5 min) it goes to castor-dlq (kept 7 days, no replay tool). Settings
        # unreadable / invalid -> 503 too (fail closed). Runs already dispatched are not touched. Order (RT F1):
        # emergency stop -> dedupe (read-only: a redelivery of a dispatched event still acks) -> maintenance ->
        # autonomous ledger / refactor claim (so a refused event leaves no refactor_intake claim behind).
        maintenance_detail = _maintenance_refusal(f"dispatch of a {intake_channel} intake event")
        if maintenance_detail is not None:
            logger.warning(f"Intake for '{payload.get('product_id')}' refused: {maintenance_detail['code']}")
            raise HTTPException(status_code=503, detail=maintenance_detail)

        # RESUME-DEVELOPER-TASK-DAG: after the dedupe (a redelivery of a dispatched event still acks) and before anything
        # below writes, so a refused event leaves no claim, access record or compliance selection behind. 422 like the
        # refusal above: redelivered until the dead-letter policy moves it to castor-dlq.
        try:
            _verify_intake_request_id(fs_client, payload)
        except _intake_policy.IntakeRejected as rejected:
            logger.warning(f"Intake event refused: {rejected.status} ({rejected.detail})")
            raise HTTPException(status_code=rejected.status_code, detail=rejected.body())

        # Lane 14 PR-4: autonomous channels re-check the ledger (toggle, code freeze, status; unreadable -> 503) and the
        # refactor channel opens at most one request per product and findings digest.
        if intake_channel in _intake_policy.AUTONOMOUS_CHANNELS:
            suppressed = _autonomous_intake_suppression(fs_client, intake_channel, payload)
            if suppressed:
                logger.info(f"Autonomous intake for '{payload.get('product_id')}' suppressed: {suppressed}")
                return {"status": suppressed}

        # RT14-14 (owner 11-14): a late or redelivered event is checked against the workload's and the run's CURRENT
        # lifecycle when it arrives, before anything below writes or takes a build slot. A DECOMMISSIONED / ARCHIVED
        # workload or an ended run is refused typed and acked (never re-vended into a new billed project); its slot,
        # if it holds one, is freed.
        lifecycle_refusal = _refuse_gone_or_ended_run(fs_client, payload)
        if lifecycle_refusal is not None:
            return lifecycle_refusal

        # RT14-02: a non-autonomous event never targets the platform workload (is_castor, or a record naming the host
        # project): vending would reuse the host project (invariant 5). Autonomous channels refuse it in their ledger
        # re-check above. Unreadable -> 503 (Pub/Sub retries), never dispatched unchecked.
        if intake_channel not in _intake_policy.AUTONOMOUS_CHANNELS:
            _refuse_platform_workload_target(fs_client, payload, project_id)

        # OSS-D23: a new workload (no document yet) from a non-autonomous channel gets the private platform default
        # access record before anything else writes its document (autonomous channels act on existing workloads).
        seed_pid = payload.get("product_id")
        if intake_channel not in _intake_policy.AUTONOMOUS_CHANNELS and isinstance(seed_pid, str) and seed_pid.strip():
            try:
                # Owner 10-20: only a Drive intake has a platform-verified submitter (the file owner recorded by the
                # poller); every other channel lists nobody (a GitHub login is not a Google identity).
                from shared.access_policy import verified_submitter_member

                submitter_email = (_drive_verified_submitter_email(fs_client, payload.get("trace_id"), seed_pid.strip())
                                   if intake_channel == "google_docs" else None)
                submitter = verified_submitter_member(submitter_email)
                # RT14 D3 (owner 11-14): the Drive submitter becomes the NEW workload's Workload Manager (assigned
                # atomically with its creation), so their follow-up specs pass the poller's workload check.
                manager = (_drive_submitter_manager(fs_client, submitter_email, seed_pid.strip())
                           if submitter is not None else None)
                seeded_branch = _seed_platform_default_access(fs_client, seed_pid.strip(), submitter,
                                                              "drive_file_owner" if submitter else None,
                                                              manager=manager)
                # FD-4CI-b-R1: the run of a workload seeded here deploys its seeded branch (the workflow's target_branch
                # argument; absent it defaults to main). An existing workload's event is forwarded unchanged.
                if seeded_branch and not payload.get("target_branch"):
                    payload["target_branch"] = seeded_branch
            except GateError as seed_err:
                raise HTTPException(status_code=503, detail=seed_err.message)

        # compliance-profile-explicit (RT F4): an explicit profile on the event is stored on the workload before
        # dispatch, so it takes effect even when the deployed workflow does not forward `compliance_profile` yet (the
        # audit reads the stored selection). Unwritable -> 503 (Pub/Sub retries, then DLQ), never dropped.
        intake_profile = payload.get("compliance_profile")
        if intake_profile:
            intake_pid = payload.get("product_id")
            if not isinstance(intake_pid, str) or not intake_pid.strip():
                raise HTTPException(status_code=422, detail={
                    "status": "SUPPRESSED:INVALID_COMPLIANCE_PROFILE",
                    "detail": "an intake event with compliance_profile needs product_id"})
            try:
                _store_compliance_selection(fs_client, intake_pid, intake_profile, requested_via="intake",
                                            trace_id=str(payload.get("trace_id") or ""))
            except OperatorActionRequiredError as down:
                # CP-11: a downgrade waits for the admin approval card; no pipeline is started (acked, not retried).
                logger.warning(f"Intake for '{intake_pid}' refused: {down.message}")
                return {"status": "SUPPRESSED:" + str(down.reason), "approval_id": down.details.get("approval_id")}
            except GateError as cp_err:
                raise HTTPException(status_code=503, detail=f"compliance profile selection not stored ({cp_err.message})")

        # BUILD-ADMISSION-QUEUE (G4): an LLM-heavy run takes a build slot here, after every gate above and before any
        # workflow starts (never inside a running stage). Idempotent per trace: a run the Control Center admitted, or
        # a queued run being dispatched, already holds its slot. No slot -> recorded QUEUED and acked (no execution);
        # it is dispatched when a running build ends. Store unavailable -> 503 (Pub/Sub retries), never unlimited.
        queued = _admit_intake_run(fs_client, payload, intake_channel)
        if queued is not None:
            return queued

        if project_id:
            try:
                from google.cloud import workflows_v1
                from google.cloud.workflows import executions_v1

                client = executions_v1.ExecutionsClient()
                parent = client.workflow_path(project_id, region, workflow_name)

                # Inject dynamic live Cloud Run service URLs
                payload["gateway_url"] = resolve_service_url("orchestrator-gateway-service")
                payload["vending_mcp_url"] = resolve_service_url("project-repo-vending-service")
                payload["workspace_mcp_url"] = resolve_service_url("mcp-workspace-connector")
                payload["terraform_mcp_url"] = resolve_service_url("mcp-terraform-server")
                payload["infracost_mcp_url"] = resolve_service_url("mcp-infracost-server")
                payload["github_mcp_url"] = resolve_service_url("mcp-github-toolserver")
                payload["kubernetes_mcp_url"] = resolve_service_url("mcp-kubernetes-server")
                payload["compliance_mcp_url"] = resolve_service_url("mcp-compliance-server")
                payload["dlq_topic"] = f"projects/{project_id}/topics/castor-dlq"

                execution = executions_v1.Execution(argument=json.dumps(payload))
                response = client.create_execution(parent=parent, execution=execution)
                logger.info(f"Triggered Cloud Workflows execution: {response.name}")

                # Ensure initial pipeline_executions document exists in Firestore for Flight Deck tracking
                trace_id = payload.get("trace_id")
                product_id = payload.get("product_id")
                execution_mode = str(payload.get("execution_mode") or "FULL").upper()
                workflow_exec_id = response.name.split("/")[-1]
                # SAT-43: the full name too (projects/P/locations/L/workflows/W/executions/E): the Control Center
                # cancels / reads the execution by name over the Workflows REST API. The id stays for every reader.
                workflow_exec_name = response.name
                now_iso = datetime.now(timezone.utc).isoformat()
                intake_request_id = _intake_policy.run_request_id(payload)   # RESUME-DEVELOPER-TASK-DAG
                if trace_id:
                    try:
                        from google.cloud import firestore
                        fs_client = firestore.Client(project=project_id)
                        pe_ref = fs_client.collection("pipeline_executions").document(trace_id)
                        pe_doc = pe_ref.get()
                        # BUILD-ADMISSION-QUEUE: a run that waited for a build slot has a QUEUED record. With stages
                        # (a Control Center relaunch pre-seed) it is attached and set running below; without (the
                        # queued record of a new build) the full initial record is written as for a new run.
                        stored_pe = (pe_doc.to_dict() or {}) if pe_doc.exists else {}
                        was_queued = stored_pe.get("status") == _build_admission.RUN_STATUS_QUEUED
                        queued_without_stages = was_queued and not stored_pe.get("stages")

                        if pe_doc.exists and (pe_doc.to_dict() or {}).get("error_class") == DEPLOY_DISPATCH_OUTCOME_UNKNOWN:
                            # deploy-dispatch S1: the CC marked this re-apply FAILED because its publish wait timed
                            # out, but the message was delivered: the run is live, so the record is running again.
                            pe_ref.set(_deploy_dispatch_revived_update(firestore, workflow_exec_id, workflow_exec_name),
                                       merge=True)
                            logger.info(f"Re-opened pre-seeded pipeline_execution {trace_id} "
                                        f"({DEPLOY_DISPATCH_OUTCOME_UNKNOWN} -> ACTIVE, {workflow_exec_id})")
                        elif pe_doc.exists and not queued_without_stages:
                            # Pre-seeded by Control Center (e.g. Fast-Path IaC): preserve stages and attach workflow_execution_id
                            attach = {"workflow_execution_id": workflow_exec_id,
                                      "workflow_execution_name": workflow_exec_name}
                            # The workflow's first status write can create the record before this read does.
                            if intake_request_id and not (pe_doc.to_dict() or {}).get("request_id"):
                                attach["request_id"] = intake_request_id
                            if was_queued:   # BUILD-ADMISSION-QUEUE: the queued relaunch starts now
                                attach.update({
                                    "status": "ACTIVE", "started_at": now_iso,
                                    "current_stage": ("TERRAFORM" if execution_mode == "DEPLOY_ONLY" else
                                                      ("DEVELOPER" if execution_mode == "RESUME_DEVELOPER"
                                                       else "DISCOVERY"))})
                            pe_ref.update(attach)
                            logger.info(f"Attached workflow_execution_id {workflow_exec_id} to pre-seeded pipeline_execution {trace_id}")
                        else:
                            is_deploy_only = (execution_mode == "DEPLOY_ONLY")
                            is_resume_dev = (execution_mode == "RESUME_DEVELOPER")
                            init_exec = {
                                "trace_id": trace_id,
                                "product_id": product_id or "",
                                "feature_title": payload.get("title") or f"Initial Build: {product_id}",
                                "status": "ACTIVE",
                                "current_stage": "TERRAFORM" if is_deploy_only else ("DEVELOPER" if is_resume_dev else "DISCOVERY"),
                                "started_at": now_iso,
                                "completed_at": None,
                                "elapsed_seconds": 0.0,
                                "workflow_execution_id": workflow_exec_id,
                                "workflow_execution_name": workflow_exec_name,
                                "execution_mode": execution_mode,
                                "stages": {
                                    "discovery": {
                                        "status": "SKIPPED" if is_deploy_only else "IN_FLIGHT",
                                        "started_at": now_iso if not is_deploy_only else None,
                                        "summary": "Bypassed via Fast-Path" if is_deploy_only else "Harvesting GCP folder organization policies (0 LLM)...",
                                    },
                                    "architect": {
                                        "status": "SKIPPED" if (is_deploy_only or is_resume_dev) else "QUEUED",
                                        "summary": "Bypassed via Fast-Path" if (is_deploy_only or is_resume_dev) else "Waiting for org policy discovery",
                                    },
                                    "compliance": {
                                        "status": "SKIPPED" if (is_deploy_only or is_resume_dev) else "QUEUED",
                                    },
                                    "vending": {
                                        "status": "SKIPPED" if (is_deploy_only or is_resume_dev) else "QUEUED",
                                    },
                                    "developer": {
                                        "status": "SKIPPED" if is_deploy_only else ("IN_FLIGHT" if is_resume_dev else "QUEUED"),
                                        "started_at": now_iso if is_resume_dev else None,
                                        "summary": "Bypassed via Zero-Invocation Invariant" if is_deploy_only else None,
                                    },
                                    "qa": {
                                        "status": "SKIPPED" if is_deploy_only else "QUEUED",
                                    },
                                    "terraform": {
                                        "status": "QUEUED",
                                        "summary": "Fast-Path IaC Re-Apply queued" if is_deploy_only else None,
                                    },
                                    "sre": {
                                        "status": "QUEUED",
                                    },
                                },
                                "outputs": {
                                    "github_repo": payload.get("github_repo", ""),
                                    "product_id": product_id or "",
                                    "target_project_id": payload.get("target_project_id", product_id or ""),
                                    "target_branch": payload.get("target_branch", "main"),
                                    "execution_mode": execution_mode,
                                },
                            }
                            if intake_request_id:
                                init_exec["request_id"] = intake_request_id
                            if was_queued and stored_pe.get("queued_at"):
                                init_exec["queued_at"] = stored_pe["queued_at"]   # BUILD-ADMISSION-QUEUE
                            pe_ref.set(init_exec)
                            logger.info(f"Initialized pipeline_executions record for {trace_id} ({product_id}, mode={execution_mode})")
                    except Exception as pe_init_err:
                        logger.warning(f"Could not initialize pipeline_executions record: {pe_init_err}")

                return {"status": "DISPATCHED", "execution_name": response.name}
            except ServiceUrlUnavailable as su:
                # FALLBACK-URLS: a platform URL the workflow needs is unknown -> no execution is started with a made-up
                # one; 503 so Pub/Sub retries and finally dead-letters the message.
                logger.error(f"Cloud Workflows execution not started: {su.message}")
                raise HTTPException(status_code=503, detail=f"workflow dispatch refused: {su.message} (SERVICE_URL_UNKNOWN)")
            except Exception as wkf_err:
                # Lane 17 AJ-11: a failed dispatch is a 5xx so Pub/Sub retries and finally dead-letters the message.
                logger.warning(f"Cloud Workflows execution trigger failed: {wkf_err}")
                raise HTTPException(status_code=503, detail=f"workflow dispatch failed ({type(wkf_err).__name__})")

        return {"status": "RECEIVED", "payload": payload}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to process Pub/Sub intake message: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------------------------------------------------------
# Lane 17 (FD-4AJ / FD-4R / FD-4AG): workflow gates. Decisions live in workflow_gates.py (pure, tested); these routes
# do the I/O and fail closed: store unavailable -> 503 GATE_UNAVAILABLE, never a pass.
# ------------------------------------------------------------------------------
def _store_unavailable(stage: str, err: Optional[BaseException] = None) -> GateUnavailableError:
    why = f" ({type(err).__name__})" if err is not None else ""
    return GateUnavailableError(f"{stage}: Firestore unavailable{why}", reason="STORE_UNAVAILABLE", stage=stage)


def _read_kill_switch(gdb: Any) -> Dict[str, Any]:
    """governance/platform_kill_switch -> {active, reason, set_by}. Unreadable or malformed -> GateUnavailableError."""
    if gdb is None:
        raise GateUnavailableError("kill switch unreadable: no Firestore client", reason="KILL_SWITCH_UNREADABLE",
                                   stage="kill_switch")
    try:
        snap = gdb.collection("governance").document("platform_kill_switch").get()
        data = (snap.to_dict() or {}) if snap.exists else {}
    except Exception as e:
        raise GateUnavailableError(f"kill switch unreadable ({type(e).__name__})", reason="KILL_SWITCH_UNREADABLE",
                                   stage="kill_switch") from e
    flag = data.get("emergency_stop_active")
    if flag is not None and not isinstance(flag, bool):
        raise GateUnavailableError("kill switch record is malformed (emergency_stop_active is not a boolean)",
                                   reason="KILL_SWITCH_UNREADABLE", stage="kill_switch")
    return {"active": flag is True, "reason": str(data.get("reason") or ""), "set_by": str(data.get("activated_by") or "")}


@app.get("/governance/kill-switch")
def governance_kill_switch(gdb: Any = Depends(get_governance_db)):
    """AJ-12: the workflow checks this at pipeline start and before vending, developer and deploy dispatch."""
    return _read_kill_switch(gdb)


class PreBuildGateRequest(BaseModel):
    trace_id: str
    product_id: str = Field(..., min_length=1)
    callback_url: str = Field(..., min_length=1)
    rework_cycle: int = Field(0, ge=0, le=100)
    compliance: Optional[Dict[str, Any]] = None
    finops: Optional[Dict[str, Any]] = None
    finops_error: Optional[str] = None
    policy_harvest_status: Optional[str] = None
    operator_requested: bool = False
    spec_doc_id: Optional[str] = None
    plan_markdown: Optional[str] = None
    plan_file_path: Optional[str] = None
    task_dag: List[Dict[str, Any]] = Field(default_factory=list)
    compliance_summary: Optional[str] = None

    @field_validator("trace_id", mode="before")
    @classmethod
    def _trace(cls, v: Any) -> str:
        return _fd4f_trace_id(v)


def _read_access_widening_flag(gdb: Any, product_id: str, stage: str) -> Tuple[Any, Any]:
    """L19-F4: (``workloads/{pid}.access_widening_approval``, ``workloads/{pid}.access``) as stored. A flag of None
    (absent or null) = nothing pending; any other value, valid or not, is pending (fail closed). Unreadable ->
    GateUnavailableError (503), never "none"."""
    try:
        snap = gdb.collection("workloads").document(product_id).get()
        data = (snap.to_dict() or {}) if snap.exists else {}
    except Exception as e:  # noqa: BLE001
        raise _store_unavailable(stage, e) from e
    if not isinstance(data, dict):
        return None, None
    return data.get(_wf_gates.ACCESS_WIDENING_APPROVAL_FIELD), data.get("access")


def _consume_access_widening(gdb: Any, product_id: str, trace_id: str, approval_id: str, reviewed: Any) -> None:
    """L19-F4: an APPROVED plan decision clears the one-shot widening flag, but only when it is still exactly the
    value this approval reviewed. Nothing pending -> no write. A flag the approval did not review (set or replaced
    after the approval was requested) -> 409 ``ACCESS_WIDENED_AFTER_REVIEW``: the run stops before vending and the
    flag stays for the next run. The clear is a precondition write on the version read (a concurrent PATCH makes it
    re-read, never clear the newer flag)."""
    from google.api_core import exceptions as gexc

    ref = gdb.collection("workloads").document(product_id)
    for _ in range(3):
        try:
            snap = ref.get()
            data = (snap.to_dict() or {}) if snap.exists else {}
        except Exception as e:  # noqa: BLE001
            raise _store_unavailable("plan_approval", e) from e
        current = data.get(_wf_gates.ACCESS_WIDENING_APPROVAL_FIELD) if isinstance(data, dict) else None
        if current is None:
            return
        if reviewed is None or current != reviewed:
            raise ContractViolationError(
                f"the access record of {product_id} was widened after approval {approval_id} was requested; "
                "the widening is not approved (the next run asks again)",
                reason="ACCESS_WIDENED_AFTER_REVIEW", stage="plan_approval")
        try:
            ref.update({_wf_gates.ACCESS_WIDENING_APPROVAL_FIELD: None,
                        "access_widening_last_approval": {"approval_id": approval_id, "trace_id": trace_id,
                                                          "approved_flag": reviewed,
                                                          "cleared_at": datetime.now(timezone.utc).isoformat()}},
                       option=gdb.write_option(last_update_time=snap.update_time))
            return
        except gexc.FailedPrecondition:
            continue  # the workload document changed since the read: compare again
        except Exception as e:  # noqa: BLE001
            raise _store_unavailable("plan_approval", e) from e
    raise _store_unavailable("plan_approval")


def _advisory_note(reasons: List[str], advisories: Any) -> str:
    """settings-toggles: the advisory texts on the approval card, only when COMPLIANCE_PROFILE_ADVISORY is a reason."""
    if _wf_gates.REASON_COMPLIANCE_PROFILE_ADVISORY not in reasons or not isinstance(advisories, list):
        return ""
    texts = [str(a.get("advisory")) for a in advisories if isinstance(a, dict) and a.get("advisory")]
    return (" (strict compliance gates: " + " ".join(texts) + ")") if texts else ""


def _access_advisory_note(reasons: List[str], access_advisories: List[Dict[str, Any]], omitted: int = 0) -> str:
    """ACCESS-INTERNAL-SERVICE-ADVISORY: the services named on the approval card's gate line, only when
    ACCESS_INTERNAL_SERVICE_PUBLIC is a reason (the card's amber block carries the full sentences)."""
    if _wf_gates.REASON_ACCESS_INTERNAL_SERVICE_PUBLIC not in reasons or not access_advisories:
        return ""
    more = f" and {omitted} more" if omitted else ""
    return (" (reachable from the internet although only Pub/Sub push calls them: "
            + ", ".join(a["service"] for a in access_advisories) + more + ")")


def _secret_advisory_note(reasons: List[str], secret_advisories: List[Dict[str, Any]], omitted: int = 0) -> str:
    """SECRET-INITIAL-VERSION: the secrets named on the approval card's gate line whenever the run pauses (for any
    reason) and the plan has such secrets (owner 11-10: warning-only, so they never pause the run themselves); the
    approval record keeps the full sentences in `secret_advisories` (the card's block)."""
    if not reasons or not secret_advisories:
        return ""
    more = f" and {omitted} more" if omitted else ""
    return (" (secrets the platform creates without a value: unless the workload's own infrastructure adds one, an "
            "operator must add it in Secret Manager before the app can read it: "
            + ", ".join(a["secret"] for a in secret_advisories) + more + ")")


def _plan_secret_advisories(gdb: Any, product_id: str, trace_id: str) -> List[Dict[str, Any]]:
    """SECRET-INITIAL-VERSION (owner 11-10): the plan-time warnings for the Secret Manager secrets of this trace's
    architect topology (`pipeline_executions/{trace}.architect_compute_intent.service_topology`, re-validated with
    shared.service_topology.topology_from_record) that the platform creates without a value
    (workflow_gates.secret_advisories). Topology secrets exist only in that record: without a record, or with one
    that has no topology (written before lane 10), the developer of this trace builds no topology secret either
    (compute_intent: platform default), so there is nothing to report. A document that cannot be read is
    GATE_UNAVAILABLE and a topology that does not validate is PLATFORM_DEFECT: "could not check" is never "nothing to
    report"."""
    stage = "prebuild_gate"
    details = {"product_id": product_id, "trace_id": trace_id}
    try:
        snap = gdb.collection("pipeline_executions").document(trace_id).get()
        data = (snap.to_dict() or {}) if snap.exists else {}
    except Exception as e:  # noqa: BLE001 - typed below
        raise GateUnavailableError(
            f"could not read pipeline_executions/{trace_id} for the secret advisory: {type(e).__name__}",
            reason=_wf_gates.REASON_SECRET_ADVISORY_FACTS_UNAVAILABLE, stage=stage, details=details) from e
    record = data.get("architect_compute_intent") if isinstance(data, dict) else None
    if record is None:
        return []
    if not isinstance(record, dict):
        raise PlatformDefectError(
            f"pipeline_executions/{trace_id}.architect_compute_intent is a {type(record).__name__}, not a record",
            reason=_wf_gates.REASON_SECRET_ADVISORY_FACTS_INVALID, stage=stage, details=details)
    topo_record = record.get("service_topology")
    if topo_record is None:
        return []
    try:
        from shared.service_topology import topology_from_record
        vt, diags = topology_from_record(topo_record, product_id=product_id)
        if vt is None:
            raise ValueError("; ".join(sorted({d.code for d in diags if d.severity == "error"})) or "no topology")
        advisories = _wf_gates.secret_advisories(vt)
    except Exception as e:  # noqa: BLE001 - a malformed typed fact is a platform defect, typed
        raise PlatformDefectError(
            f"the architect topology of trace '{trace_id}' does not validate for the secret advisory: "
            f"{type(e).__name__}: {e}", reason=_wf_gates.REASON_SECRET_ADVISORY_FACTS_INVALID, stage=stage,
            details=details) from e
    for adv in advisories:
        logger.warning(f"{adv['code']} for '{product_id}' ({trace_id}): {adv['message']}")
    return advisories


def _persist_prebuild_gate(gdb: Any, product_id: str, trace_id: str, gate: Dict[str, Any]) -> None:
    gdb.collection("pipeline_executions").document(trace_id).set({"prebuild_gate": gate}, merge=True)
    gdb.collection("workloads").document(product_id).set({"last_prebuild_gate": gate}, merge=True)


def _persist_task_dag(gdb: Any, product_id: str, trace_id: str, rework_cycle: int, task_dag: List[Dict[str, Any]],
                      recorded_at: str) -> None:
    """RESUME-DEVELOPER-TASK-DAG: keep this gate decision's Task DAG for a later RESUME_DEVELOPER run (a write failure
    reaches the gate's fail-loud block). A DAG too large to keep is logged and recorded with its status: this build
    carries its DAG in the workflow and goes on; a resume of it stops (`/agent/resume/outcome`)."""
    record = _wf_gates.task_dag_record(product_id=product_id, trace_id=trace_id, rework_cycle=rework_cycle,
                                       task_dag=task_dag, recorded_at=recorded_at)
    if record["status"] == _wf_gates.TASK_DAG_TOO_LARGE:
        logger.error(f"{_wf_gates.PERSISTED_TASK_DAG_TOO_LARGE}: the Task DAG of {trace_id} is {record['size_bytes']} "
                     f"bytes (limit {_wf_gates.MAX_PERSISTED_TASK_DAG_BYTES}); this build goes on, but it cannot be "
                     "resumed (a relaunch needs a full build)")
    (gdb.collection("workloads").document(product_id)
     .collection(_wf_gates.TASK_DAG_COLLECTION).document(trace_id).set(record))


@app.post("/events/pre-build-gate")
def pre_build_gate(req: PreBuildGateRequest, gdb: Any = Depends(get_governance_db)):
    """FD-4AG (+ compliance HITL + operator request): decide whether the run may build or must WAIT for a human.

    AWAIT_APPROVAL creates approval_requests/appr-plan-{trace}-{cycle} (deterministic id, create(); a retried POST
    finds the same record and refreshes its callback while still PENDING, RT F7). The decision is persisted on
    pipeline_executions/{trace}.prebuild_gate and workloads/{pid}.last_prebuild_gate (RT F1, read by resume).

    L19-F4: a pending ``workloads/{pid}.access_widening_approval`` flag (set by a widening admin access PATCH) adds
    ``ACCESS_WIDENED``; the approval record keeps the flag value it reviews (``access_widening_reviewed``) so only an
    APPROVED decision on exactly that value clears it. The workload document unreadable -> 503 (never a pass).
    """
    # settings-toggles: governance.strict_compliance_gates (strict read, unreadable -> on) is read only when the
    # compliance decision carries profile advisories, so a run without advisories is decided exactly as before.
    advisories = req.compliance.get("profile_advisories") if isinstance(req.compliance, dict) else None
    advisories_block = bool(isinstance(advisories, list) and advisories and _compliance_advisories_block())

    def _evaluate(access_widening_pending: bool, secret_advisories: Optional[List[Dict[str, Any]]] = None):
        return _wf_gates.evaluate_pre_build_gate(
            compliance=req.compliance, finops=req.finops, finops_error=req.finops_error,
            policy_harvest_status=req.policy_harvest_status, operator_requested=req.operator_requested,
            access_widening_pending=access_widening_pending, advisories_block=advisories_block,
            secret_advisories=secret_advisories)

    try:
        _evaluate(False)  # contract first: a missing compliance decision is 422 whatever the store holds
    except ValueError as ve:
        raise HTTPException(status_code=422, detail={"error_class": "CONTRACT_VIOLATION", "reason": "COMPLIANCE_MISSING",
                                                     "stage": "prebuild_gate", "summary": str(ve)})
    # ACCESS-INTERNAL-SERVICE-ADVISORY: checked and copied onto the plan approval card (a non-empty list is the gate
    # reason ACCESS_INTERNAL_SERVICE_PUBLIC, decided in `_evaluate`).
    try:
        access_advisories = _wf_gates.access_advisories_of(req.compliance)
        access_advisories_omitted = _wf_gates.access_advisories_omitted_of(req.compliance)
    except ValueError as ve:
        raise HTTPException(status_code=422, detail={"error_class": "CONTRACT_VIOLATION",
                                                     "reason": "ACCESS_ADVISORIES_INVALID", "stage": "prebuild_gate",
                                                     "summary": str(ve)})
    if gdb is None:
        raise _store_unavailable("prebuild_gate")
    widening_flag, current_access = _read_access_widening_flag(gdb, req.product_id, "prebuild_gate")
    # SECRET-INITIAL-VERSION: secrets the plan's topology creates without a value (gate reason SECRET_CREATED_EMPTY)
    secret_advisories, secret_advisories_omitted = _wf_gates.capped_secret_advisories(
        _plan_secret_advisories(gdb, req.product_id, req.trace_id))
    decision, reasons = _evaluate(widening_flag is not None, secret_advisories)
    now_iso = datetime.now(timezone.utc).isoformat()
    approval_id = ""
    try:
        if decision == _wf_gates.GATE_AWAIT_APPROVAL:
            from google.api_core import exceptions as gexc

            approval_id = _wf_gates.plan_approval_id(req.trace_id, req.rework_cycle)
            ref = gdb.collection("approval_requests").document(approval_id)
            record = {
                "approval_id": approval_id,
                "approval_type": "ARCHITECTURAL_PLAN",
                "product_id": req.product_id,
                "trace_id": req.trace_id,
                "status": "PENDING",
                "callback_url": req.callback_url,
                "gate_reasons": reasons,
                "finops_estimate": req.finops,
                "finops_error": req.finops_error or "",
                # Bundle RT F5: display string for the card (WS-2), the number alongside
                "cost_delta_monthly": _wf_gates.cost_display(req.finops),
                "cost_delta_monthly_usd": _wf_gates.numeric_cost(req.finops),
                "risk_assessment": ("Pre-build gate: " + ", ".join(reasons) + _advisory_note(reasons, advisories)
                                    + _access_advisory_note(reasons, access_advisories, access_advisories_omitted)
                                    + _secret_advisory_note(reasons, secret_advisories, secret_advisories_omitted)),
                "plan_markdown": req.plan_markdown,
                "plan_file_path": req.plan_file_path,
                "task_dag": req.task_dag,
                "compliance_summary": req.compliance_summary,
                "rework_cycle": req.rework_cycle,
                "spec_doc_id": req.spec_doc_id or "",
                # L19-F4: the access-widening flag this approval reviews (None: no widening pending at request time)
                "access_widening_reviewed": widening_flag,
                # RT R2: what the approver is asked to approve (shown on the CC card): the flag (baseline mode and
                # members, added members) and the record the build will use.
                "access_under_review": ({"flag": widening_flag, "current_access": current_access}
                                        if widening_flag is not None else None),
                # ACCESS-INTERNAL-SERVICE-ADVISORY: the compliance stage's typed access warnings ([] = none)
                "access_advisories": access_advisories,
                "access_advisories_omitted": access_advisories_omitted,
                # SECRET-INITIAL-VERSION: the topology's secrets created without a value ([] = none)
                "secret_advisories": secret_advisories,
                "secret_advisories_omitted": secret_advisories_omitted,
                "created_at": time.time(),
                "created_at_iso": now_iso,
                "requested_at": now_iso,
            }
            try:
                ref.create(record)
            except gexc.AlreadyExists:
                existing = ref.get()
                ex = (existing.to_dict() or {}) if existing.exists else {}
                if ex.get("trace_id") != req.trace_id or ex.get("product_id") != req.product_id:
                    raise ContractViolationError(f"approval {approval_id} belongs to another run",
                                                 reason="APPROVAL_ID_COLLISION", stage="prebuild_gate")
                if ex.get("status") == "PENDING" and ex.get("callback_url") != req.callback_url:
                    ref.set({"callback_url": req.callback_url}, merge=True)
            gdb.collection("pipeline_executions").document(req.trace_id).set({
                "state": "AWAITING_PLAN_APPROVAL", "current_step": "AWAITING_PLAN_APPROVAL",
                "approval_id": approval_id, "updated_at": time.time()}, merge=True)
        gate = {"status": decision, "approval_id": approval_id, "trace_id": req.trace_id, "product_id": req.product_id,
                "gate_reasons": reasons, "rework_cycle": req.rework_cycle, "decided_at": now_iso}
        if secret_advisories:   # SECRET-INITIAL-VERSION: kept with the decision whether or not it paused the run
            gate.update(secret_advisories=secret_advisories, secret_advisories_omitted=secret_advisories_omitted)
        # Every gate decision (PASS and AWAIT_APPROVAL, so each rework cycle's DAG too), before the gate a resume reads
        _persist_task_dag(gdb, req.product_id, req.trace_id, req.rework_cycle, req.task_dag, now_iso)
        _persist_prebuild_gate(gdb, req.product_id, req.trace_id, gate)
    except GateError:
        raise
    except Exception as e:
        logger.error(f"Pre-build gate persistence failed for {req.trace_id}: {e}", exc_info=True)
        raise _store_unavailable("prebuild_gate", e) from e
    return {"status": "SUCCESS", "decision": decision, "gate_reasons": reasons, "approval_id": approval_id}


class PreBuildDecisionRequest(BaseModel):
    trace_id: str
    product_id: str = Field(..., min_length=1)
    approval_id: str = Field(..., min_length=1, max_length=200)
    decision: str

    @field_validator("trace_id", mode="before")
    @classmethod
    def _trace(cls, v: Any) -> str:
        return _fd4f_trace_id(v)


@app.post("/events/pre-build-gate/decision")
def pre_build_gate_decision(req: PreBuildDecisionRequest, gdb: Any = Depends(get_governance_db)):
    """RT F1: persist the plan-approval outcome only when it equals the approval record (exact). While the Control
    Center is still writing its decision (status PENDING/DECIDING) -> 503 DECISION_PENDING (the workflow retries)."""
    if req.decision not in _wf_gates.PLAN_DECISIONS:
        raise ContractViolationError(f"unknown plan decision {req.decision!r}", reason="UNKNOWN_DECISION",
                                     stage="plan_approval")
    if gdb is None:
        raise _store_unavailable("plan_approval")
    try:
        snap = gdb.collection("approval_requests").document(req.approval_id).get()
        record = (snap.to_dict() or {}) if snap.exists else None
    except Exception as e:
        raise _store_unavailable("plan_approval", e) from e
    if record is None:
        raise ContractViolationError(f"approval {req.approval_id} not found", reason="APPROVAL_NOT_FOUND",
                                     stage="plan_approval")
    if record.get("trace_id") != req.trace_id or record.get("product_id") != req.product_id:
        raise ContractViolationError(f"approval {req.approval_id} belongs to another run", reason="TRACE_MISMATCH",
                                     stage="plan_approval")
    status_now = record.get("status")
    if status_now in ("PENDING", "DECIDING"):
        raise GateUnavailableError(f"approval {req.approval_id} decision not yet recorded ({status_now})",
                                   reason="DECISION_PENDING", stage="plan_approval")
    if status_now != req.decision:
        raise ContractViolationError(f"callback decision {req.decision} != approval record status {status_now}",
                                     reason="DECISION_MISMATCH", stage="plan_approval")
    if req.decision == "APPROVED":
        # L19-F4: the approval of a widened access record is consumed here (once), before the gate is persisted, so a
        # resume can never reuse an APPROVED gate while the widening it did not review is still pending.
        _consume_access_widening(gdb, req.product_id, req.trace_id, req.approval_id,
                                 record.get("access_widening_reviewed"))
    gate = {"status": req.decision, "approval_id": req.approval_id, "trace_id": req.trace_id,
            "product_id": req.product_id, "gate_reasons": record.get("gate_reasons") or [],
            "rework_cycle": record.get("rework_cycle", 0), "decided_at": datetime.now(timezone.utc).isoformat()}
    try:
        _persist_prebuild_gate(gdb, req.product_id, req.trace_id, gate)
    except Exception as e:
        raise _store_unavailable("plan_approval", e) from e
    return {"status": "SUCCESS", "decision": req.decision}


class ApprovalGateRequest(BaseModel):
    trace_id: str
    product_id: str = Field(..., min_length=1)
    approval_type: str
    callback_url: str = Field(..., min_length=1)
    recheck_n: int = Field(0, ge=0, le=10)
    reason: Optional[str] = None
    target_region: Optional[str] = None
    violations: List[Any] = Field(default_factory=list)
    remediation: Optional[Any] = None
    quota_source: Optional[str] = None

    @field_validator("trace_id", mode="before")
    @classmethod
    def _trace(cls, v: Any) -> str:
        return _fd4f_trace_id(v)


@app.post("/events/approval-request")
def register_approval_gate(req: ApprovalGateRequest, gdb: Any = Depends(get_governance_db)):
    """AJ-8: the quota gate's approval record (the only writer; the workflow used to post a callback_url to
    /events/workflow-status, which dropped it, so the gate could never resume). Deterministic id
    appr-quota-{trace}-{recheck} created once (RT F7). Only approval_type QUOTA_GATE is accepted."""
    if req.approval_type != "QUOTA_GATE":
        raise ContractViolationError(f"approval_type {req.approval_type!r} is not accepted here",
                                     reason="UNKNOWN_APPROVAL_TYPE", stage="quota_gate")
    if gdb is None:
        raise _store_unavailable("quota_gate")
    approval_id = _wf_gates.quota_approval_id(req.trace_id, req.recheck_n)
    now_iso = datetime.now(timezone.utc).isoformat()
    record = {
        "approval_id": approval_id,
        "approval_type": "QUOTA_GATE",
        "product_id": req.product_id,
        "trace_id": req.trace_id,
        "status": "PENDING",
        "callback_url": req.callback_url,
        "gate_reasons": [req.reason] if req.reason else [],
        "target_region": req.target_region or "",
        "violations": req.violations,
        "remediation": req.remediation,
        "quota_source": req.quota_source or "",
        "recheck_n": req.recheck_n,
        "cost_delta_monthly": "$0.00/mo",
        "risk_assessment": f"Quota gate ({req.reason or 'QUOTA'}): APPROVE re-checks quota, REJECT stops the run",
        "created_at": time.time(),
        "created_at_iso": now_iso,
        "requested_at": now_iso,
    }
    try:
        from google.api_core import exceptions as gexc

        ref = gdb.collection("approval_requests").document(approval_id)
        try:
            ref.create(record)
        except gexc.AlreadyExists:
            existing = ref.get()
            ex = (existing.to_dict() or {}) if existing.exists else {}
            if ex.get("trace_id") != req.trace_id or ex.get("product_id") != req.product_id:
                raise ContractViolationError(f"approval {approval_id} belongs to another run",
                                             reason="APPROVAL_ID_COLLISION", stage="quota_gate")
            if ex.get("status") == "PENDING" and ex.get("callback_url") != req.callback_url:
                ref.set({"callback_url": req.callback_url}, merge=True)
        gdb.collection("pipeline_executions").document(req.trace_id).set({
            "state": "AWAITING_QUOTA_APPROVAL", "current_step": "AWAITING_QUOTA_APPROVAL",
            "approval_id": approval_id, "updated_at": time.time()}, merge=True)
    except GateError:
        raise
    except Exception as e:
        raise _store_unavailable("quota_gate", e) from e
    return {"status": "SUCCESS", "approval_id": approval_id}


class ResumeOutcomeRequest(BaseModel):
    trace_id: str
    product_id: str = Field(..., min_length=1)

    @field_validator("trace_id", mode="before")
    @classmethod
    def _trace(cls, v: Any) -> str:
        return _fd4f_trace_id(v)


@app.post("/agent/resume/outcome")
def resume_outcome(req: ResumeOutcomeRequest, gdb: Any = Depends(get_governance_db)):
    """RT F1 / R-5: a RESUME_DEVELOPER run reuses the prior FULL build's persisted pre-build gate (PASS / APPROVED)
    and the compliance decision of the SAME trace. Anything else -> 503 GATE_UNAVAILABLE "run a full build".
    RESUME-DEVELOPER-TASK-DAG: the same stop when the gate's Task DAG is not kept, before any developer spend: QA would
    refuse the run later for lack of it. The DAG stays out of the answer, so out of the workflow's data; a developer
    dispatch that needs it reads the same record (`_resume_developer_task_dag`)."""
    if gdb is None:
        raise _store_unavailable("resume")
    try:
        w_snap = gdb.collection("workloads").document(req.product_id).get()
        workload = (w_snap.to_dict() or {}) if w_snap.exists else {}
        gate = workload.get("last_prebuild_gate") if isinstance(workload.get("last_prebuild_gate"), dict) else None
        record = None
        dag_record = None
        gate_trace = (gate or {}).get("trace_id")
        if isinstance(gate_trace, str) and gate_trace:
            workload_ref = gdb.collection("workloads").document(req.product_id)
            c_snap = workload_ref.collection("compliance_audits").document(gate_trace).get()
            record = (c_snap.to_dict() or {}) if c_snap.exists else None
            d_snap = workload_ref.collection(_wf_gates.TASK_DAG_COLLECTION).document(gate_trace).get()
            dag_record = (d_snap.to_dict() or {}) if d_snap.exists else None
    except Exception as e:
        raise _store_unavailable("resume", e) from e
    problems = list(_wf_gates.resume_outcome_problems(product_id=req.product_id, compliance_record=record,
                                                      prebuild_gate=gate))
    if gate:
        _dag, dag_problem = _wf_gates.persisted_task_dag(dag_record, product_id=req.product_id, prebuild_gate=gate)
        if dag_problem:
            problems.append(dag_problem)
    if workload.get(_wf_gates.ACCESS_WIDENING_APPROVAL_FIELD) is not None:
        # L19-F4: a widened access record must go through the plan gate; a resume would skip it.
        problems.append("ACCESS_WIDENING_PENDING")
    if problems:
        raise GateUnavailableError("no reusable full-build gate decision for RESUME_DEVELOPER; run a full build",
                                   reason="RESUME_GATE_UNAVAILABLE", stage="resume", details={"problems": problems})
    try:  # the gate this run reuses, for QA's Task DAG lookup (merge: the run's document already exists)
        gdb.collection("pipeline_executions").document(req.trace_id).set({_wf_gates.RESUME_GATE_FIELD: gate}, merge=True)
    except Exception as e:
        raise _store_unavailable("resume", e) from e
    return {"status": "SUCCESS", "source_trace_id": gate_trace, "prebuild_gate": gate,
            "compliance": _wf_gates.compliance_ingress_view(record)}


class DeployOnlyGateRequest(BaseModel):
    trace_id: str
    product_id: str = Field(..., min_length=1)
    branch: str = Field(..., min_length=1, max_length=255)

    @field_validator("trace_id", mode="before")
    @classmethod
    def _trace(cls, v: Any) -> str:
        return _fd4f_trace_id(v)


def _express_destroy_refusal_open(workload: Any) -> bool:
    """EXP-7 / RT14-07: an Express workload whose last deploy was refused with DESTROY_REQUIRES_APPROVAL and not yet
    cleared by an Express re-submit (`destroy_requires_approval` is a non-empty dict). Same rule as the Control
    Center's `express_destroy_refusal_open` (apps/control-center/routes/workloads.py)."""
    if not isinstance(workload, dict) or workload.get("creation_mode") != "EXPRESS":
        return False
    open_refusal = workload.get("destroy_requires_approval")
    return isinstance(open_refusal, dict) and bool(open_refusal)


@app.post("/governance/deploy-only-gate")
def deploy_only_gate(req: DeployOnlyGateRequest, gdb: Any = Depends(get_governance_db)):
    """RT F2: DEPLOY_ONLY re-applies reviewed IaC only: the workload's default branch (or, once lane 16's release
    ledger lands, a branch with exactly one MERGED ledger entry). Otherwise 403 POLICY_REJECTED.
    FD-4DT: also 403 POLICY_REJECTED (reason ACCESS_WIDENING_PENDING) while an access widening waits for its plan
    approval (L19-F4), because the deploy applies the current access record."""
    if gdb is None:
        raise _store_unavailable("deploy_only_gate")
    try:
        snap = gdb.collection("workloads").document(req.product_id).get()
        workload = (snap.to_dict() or {}) if snap.exists else None
    except Exception as e:
        raise _store_unavailable("deploy_only_gate", e) from e
    if workload is None:
        raise ContractViolationError(f"workload {req.product_id} not found", reason="WORKLOAD_NOT_FOUND",
                                     stage="deploy_only_gate")
    if workload.get(_wf_gates.ACCESS_WIDENING_APPROVAL_FIELD) is not None:
        # FD-4DT + L19-F4: a DEPLOY_ONLY deploy applies the workload's CURRENT access record (tf-applier renders it),
        # and DEPLOY_ONLY skips the pre-build gate, so a widening waiting for its plan approval is never applied
        # here: only a full build, whose plan approval clears the flag, applies it.
        raise PolicyRejectedError(
            f"DEPLOY_ONLY refused for {req.product_id}: the access record was widened and the widening is not "
            "approved yet; relaunch with a full build (Full Swarm Rebuild) so the plan approval can clear it",
            reason="ACCESS_WIDENING_PENDING", stage="deploy_only_gate")
    if _express_destroy_refusal_open(workload):
        # EXP-7 / RT14-07: the Express configuration whose deploy was refused for unapproved deletions or replacements
        # is committed; a DEPLOY_ONLY apply carries no destroy policy and would apply it. Every DEPLOY_ONLY run passes
        # this gate, whichever path started it (the Control Center refuses the same state before dispatch).
        raise PolicyRejectedError(
            f"DEPLOY_ONLY refused for {req.product_id}: its last Express deploy was refused because it would delete or "
            "replace existing resources (DESTROY_REQUIRES_APPROVAL); re-submit it in Express mode without the change, "
            "or with approved_removals set to exactly those addresses",
            reason="DESTROY_REQUIRES_APPROVAL", stage="deploy_only_gate")
    # FD-4P: the PR ledger now exists; a non-default branch is reviewed code only if its single ledger entry MERGED.
    try:
        ledger_entries = vcs_ledger.entries_for_product(gdb, req.product_id)
    except vcs_ledger.LedgerError as e:
        raise _store_unavailable("deploy_only_gate", e) from e
    # RT F7: only entries of the workload's own provider + repository count.
    vcs_kind = _workload_vcs_kind(workload)
    try:  # the same repository resolution the developer and release steps key the ledger with
        repo_key = vcs_ledger.repo_key(developer_agent.get_full_repo_name(req.product_id))
    except Exception:  # noqa: BLE001 - no resolvable repository => no ledger entry can count
        repo_key = None
    ledger_entries = [e for e in ledger_entries if e.get("provider") == vcs_kind and e.get("repo_key") == repo_key]
    allowed, why = _wf_gates.deploy_only_allowed(branch=req.branch, workload=workload, ledger_entries=ledger_entries)
    if not allowed:
        raise PolicyRejectedError(f"DEPLOY_ONLY refused for branch {req.branch!r}: {why}", reason=why,
                                  stage="deploy_only_gate")
    return {"status": "ALLOW", "reason": why, "branch": req.branch}


@app.post("/callback")
def handle_workflow_callback(callback_data: Dict[str, Any]):
    """Receives callback responses for suspended workflow executions."""
    logger.info(f"Received workflow callback: {callback_data}")
    return {"status": "CALLBACK_RECEIVED", "data": callback_data}


class WorkflowStatusUpdate(BaseModel):
    trace_id: str
    product_id: Optional[str] = None
    status: Optional[str] = None  # "ACTIVE", "SUCCEEDED", "FAILED"
    current_stage: Optional[str] = None
    stage_name: Optional[str] = None
    stage_status: Optional[str] = None
    stage_summary: Optional[str] = None
    service_url: Optional[str] = None
    pull_request_url: Optional[str] = None
    state_file: Optional[str] = None
    error_detail: Optional[str] = None
    workflow_execution_id: Optional[str] = None
    # Lane 17 RT F5: the workflow's single failure handler sends the typed failure; persisted for operators and the
    # Control Center retrigger router (route on error_class, not on error text).
    error_class: Optional[str] = None
    failed_stage: Optional[str] = None
    reason: Optional[str] = None


# DEPLOY-HEALTH-WORDING (owner 10-27): nothing in the pipeline probes the deployed service (no request to its URL,
# no readiness check), so a successful run says the service was deployed, never "verified healthy". A run that did
# probe would need its own typed result to say more; none exists today (post-QA pre-flight D10).
SRE_IDLE_SUMMARY = "Deployed (no health probe ran); incident remediation idle"
# The FinOps SUCCESS text is fixed at its source (workflows/main_orchestrator.yaml, before the RC); no gateway override.
_STAGE_SUMMARY_OVERRIDES: Dict[Tuple[Optional[str], Optional[str]], str] = {}


def _stage_summary(stage_name: Optional[str], stage_status: Optional[str], summary: Optional[str]) -> Optional[str]:
    """The stage summary to store: the gateway's own text for a typed (stage, status) pair it owns, else the
    workflow's text unchanged. Exact match on the typed fields only; the summary text is never inspected."""
    if not summary:
        return summary
    return _STAGE_SUMMARY_OVERRIDES.get((stage_name, stage_status), summary)


# deploy-dispatch S1: the class the Control Center /deploy-infra writes when its publish wait timed out (the message
# may still be delivered). Same literal as DEPLOY_DISPATCH_OUTCOME_UNKNOWN in apps/control-center/routes/workloads.py.
DEPLOY_DISPATCH_OUTCOME_UNKNOWN = "DEPLOY_DISPATCH_OUTCOME_UNKNOWN"


def _deploy_dispatch_revived_update(firestore_mod: Any, workflow_exec_id: str,
                                    workflow_exec_name: Optional[str] = None) -> Dict[str, Any]:
    """The merge-set that turns an OUTCOME_UNKNOWN re-apply record back into a running one once its workflow starts:
    ACTIVE / TERRAFORM / terraform QUEUED, and the failure fields the CC wrote are deleted."""
    delete = firestore_mod.DELETE_FIELD
    return {
        "workflow_execution_id": workflow_exec_id,
        "workflow_execution_name": workflow_exec_name or delete,  # SAT-43: full name (the CC cancels by name)
        "status": "ACTIVE",
        "current_stage": "TERRAFORM",
        "error_class": delete,
        "error": delete,
        "failed_stage": delete,
        "completed_at": delete,
        "stages": {
            "terraform": {"status": "QUEUED", "summary": "Fast-Path IaC Re-Apply queued (build event delivered)",
                          "error_class": delete, "completed_at": delete},
            "sre": {"status": "QUEUED", "summary": delete},
        },
    }


def _release_deployment_lock_for_trace(db: Any, product_id: Optional[str], trace_id: str, status: str,
                                       now_iso: str) -> None:
    """FD deploy-dispatch: a Fast-Path re-apply (Control Center /deploy-infra) takes workloads/{pid}.deployment_lock
    tagged with its trace_id. When that trace reports a terminal status (SUCCEEDED or FAILED) the lock is released
    here, so it no longer blocks the next re-apply for its full 15-minute expiry (which stays as the backstop).

    Released only when the lock is held AND carries this trace_id (a lock taken by another re-apply, e.g. a forced
    one, is left alone), with a precondition on the version read (a concurrent re-lock wins). Best effort: never
    fails the status update."""
    if not product_id or not trace_id:
        return
    try:
        ref = db.collection("workloads").document(product_id)
        snap = ref.get()
        if not snap.exists:
            return
        lock = dict((snap.to_dict() or {}).get("deployment_lock") or {})
        if not lock.get("is_locked") or lock.get("trace_id") != trace_id:
            return
        lock.update({"is_locked": False, "released_at": now_iso, "release_reason": f"WORKFLOW_{status}"})
        ref.update({"deployment_lock": lock}, option=db.write_option(last_update_time=snap.update_time))
        logger.info(f"Released deployment lock for '{product_id}' (trace {trace_id} {status})")
    except Exception as lock_err:
        logger.warning(f"Could not release deployment lock for '{product_id}' (trace {trace_id}): "
                       f"{type(lock_err).__name__}; it expires after 15 minutes")


# WORKLOAD-STATUS-PRE-DEPLOY-FAILURE: the Control Center registers a workload as PROVISIONING and vending records
# PROVISIONED; only the terraform server wrote the outcome (DEPLOYED / FAILED), so a run that stopped earlier left a
# run-in-progress word on workloads/{id} forever. Every workflow failure ends in one notify_failure call to
# /events/workflow-status, so that handler records it. Exact comparison of typed fields only: the record's status, and
# the terraform server's terraform_deployments ledger as the proof of an earlier good deploy (vending rewrites a
# DEPLOYED record to PROVISIONED on a full re-run, and `deployed_at` is also written by a failed deploy).
WORKLOAD_STATUSES_OF_AN_UNFINISHED_RUN = frozenset({"PROVISIONING", "PROVISIONED"})
WORKLOAD_STATUS_NOT_RECORDED = "WORKLOAD_STATUS_NOT_RECORDED"
_WORKLOAD_STATUS_WRITE_ATTEMPTS = 3
# The statuses the Control Center's active-run query treats as a run under way (routes/telemetry.py).
_RUN_STATUSES_UNDER_WAY = ("ACTIVE", "RUNNING", "PAUSED_RATE_LIMIT_COOLDOWN")


def _project_has_successful_deploy(db: Any, product_id: str, project_id: str) -> bool:
    """True when the terraform server recorded a SUCCESS deploy of this workload into this project. The project is part
    of the match: a workload decommissioned and vended again into a new project has deployed nothing there yet."""
    deploys = (db.collection("terraform_deployments").where("product_id", "==", product_id)
               .where("project_id", "==", project_id).where("status", "==", "SUCCESS").limit(1).stream())
    return any(True for _ in deploys)


def _run_started_at(value: Any) -> datetime:
    started = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return started if started.tzinfo else started.replace(tzinfo=timezone.utc)


def _newer_run_under_way(db: Any, product_id: str, trace_id: str, started_at: Any) -> Optional[str]:
    """The trace of a run of this workload that started after this one and has not finished, else None: the workload's
    status then belongs to that run. A start time that cannot be read raises, so the caller does not guess."""
    this_run_started = _run_started_at(started_at)
    runs = (db.collection("pipeline_executions").where("product_id", "==", product_id)
            .where("status", "in", list(_RUN_STATUSES_UNDER_WAY)).stream())
    for run in runs:
        record = run.to_dict() or {}
        if run.id != trace_id and _run_started_at(record.get("started_at") or record.get("created_at")) > this_run_started:
            return run.id
    return None


def _write_workload_failed_before_deploy(db: Any, product_id: str, trace_id: str, started_at: Any,
                                         error_class: Optional[str], error_detail: Optional[str]) -> None:
    """Sets workloads/{product_id}.status to FAILED when the run stopped while the record still holds a run-in-progress
    word, no newer run of the workload is under way, and the workload's project never had a good deploy; every other
    record is left exactly as it is. The write is conditional on the record read, and is re-read and re-decided when
    another writer got in between."""
    from google.api_core import exceptions as gexc

    ref = db.collection("workloads").document(product_id)
    for _ in range(_WORKLOAD_STATUS_WRITE_ATTEMPTS):
        snap = ref.get()
        record = (snap.to_dict() or {}) if snap.exists else {}
        if record.get("status") not in WORKLOAD_STATUSES_OF_AN_UNFINISHED_RUN:
            return
        newer_run = _newer_run_under_way(db, product_id, trace_id, started_at)
        if newer_run:
            logger.info(f"Run {trace_id} of '{product_id}' failed; status {record.get('status')} kept (newer run "
                        f"{newer_run} is under way)")
            return
        project_id = record.get("project_id")
        if project_id and _project_has_successful_deploy(db, product_id, project_id):
            logger.info(f"Run {trace_id} of '{product_id}' failed; status {record.get('status')} kept (project "
                        f"'{project_id}' has a successful deploy)")
            return
        reason = ": ".join(part for part in (error_class, error_detail) if part) or f"run {trace_id} failed"
        try:
            ref.update({"status": "FAILED", "failure_reason": reason},
                       option=db.write_option(last_update_time=snap.update_time))
        except gexc.FailedPrecondition:
            continue
        logger.info(f"Workload '{product_id}' marked FAILED: run {trace_id} stopped before a deploy")
        return
    raise RuntimeError(f"the record kept changing during {_WORKLOAD_STATUS_WRITE_ATTEMPTS} attempts")


def _record_run_failure_on_workload(db: Any, run_ref: Any, product_id: Optional[str], trace_id: str, started_at: Any,
                                    error_class: Optional[str], error_detail: Optional[str]) -> None:
    """Never raises: the caller still has the feature request to synchronize. A status that could not be recorded is
    logged and stored as typed data on the run record (fail-loudly policy 2), and the workload's record is unchanged.
    product_id must be one the event or the stored run record states, never one parsed out of the trace id."""
    try:
        if not product_id:
            raise ValueError("neither the event nor the run record names the workload")
        _write_workload_failed_before_deploy(db, product_id, trace_id, started_at, error_class, error_detail)
    except Exception as status_err:  # noqa: BLE001 - typed below; the run's own FAILED record is already written
        detail = f"{type(status_err).__name__}: {status_err}"
        logger.error(f"{WORKLOAD_STATUS_NOT_RECORDED}: run {trace_id} failed, workload {product_id!r} unchanged ({detail})")
        try:
            run_ref.set({"workload_status_error": {"code": WORKLOAD_STATUS_NOT_RECORDED, "detail": detail}}, merge=True)
        except Exception as run_err:  # noqa: BLE001 - the error log above stands
            logger.error(f"{WORKLOAD_STATUS_NOT_RECORDED}: not stored on run {trace_id} ({type(run_err).__name__})")


# SAT-13 (a): the workflow posts the release stage's PAUSED_FOR_APPROVAL heartbeat after it registers the approval
# callback (workflows/main_orchestrator.yaml notify_pr_approval_pending). A decision recorded in between must not be
# overwritten by that late heartbeat. The decided statuses are the ones the two terminal writers store:
# apps/control-center/routes/approvals.py RELEASE_STAGE_STATUS_BY_DECISION (APPROVED -> SUCCESS, REJECTED -> REJECTED)
# and _record_release_stage_merged above (SUCCESS). Exact comparison of typed fields only.
RELEASE_STAGE_NAME = "release"
RELEASE_HEARTBEAT_STATUS = "PAUSED_FOR_APPROVAL"
RELEASE_STAGE_DECIDED_STATUSES = frozenset({"SUCCESS", "REJECTED"})


def _is_release_heartbeat(stage_name: Optional[str], stage_status: Optional[str]) -> bool:
    return stage_name == RELEASE_STAGE_NAME and stage_status == RELEASE_HEARTBEAT_STATUS


def _without_release_over_decision(update_payload: Dict[str, Any],
                                   stored: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """`update_payload` minus `stages.release` when the stored release stage already holds a decided status; else the
    payload unchanged (same object). Every other field of the update is kept."""
    stages = (stored or {}).get("stages")
    release = stages.get(RELEASE_STAGE_NAME) if isinstance(stages, dict) else None
    if not (isinstance(release, dict) and release.get("status") in RELEASE_STAGE_DECIDED_STATUSES):
        return update_payload
    kept = {k: v for k, v in update_payload.items() if k != "stages"}
    other_stages = {k: v for k, v in (update_payload.get("stages") or {}).items() if k != RELEASE_STAGE_NAME}
    if other_stages:
        kept["stages"] = other_stages
    return kept


def _write_release_heartbeat(db: Any, doc_ref: Any, update_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Writes a release PAUSED_FOR_APPROVAL heartbeat in one Firestore transaction: read the run record, drop the
    release stage when a decision is already stored, then merge-set. A decision written after the read makes the
    commit abort, and the library re-runs the read (no read-then-write window). Returns what was written."""
    from google.cloud.firestore_v1 import transactional

    @transactional
    def _txn(txn):
        snap = doc_ref.get(transaction=txn)
        payload = _without_release_over_decision(update_payload, snap.to_dict() if snap.exists else None)
        if payload is not update_payload:
            logger.info(f"Release heartbeat for {doc_ref.id}: release stage already decided; stage not overwritten")
        txn.set(doc_ref, payload, merge=True)
        return payload

    return _txn(db.transaction())


def _release_build_slot_and_pump(db: Any, run_ref: Any, trace_id: str, status_word: str) -> None:
    """BUILD-ADMISSION-QUEUE: a run's terminal status frees its build slot and dispatches the oldest queued build.
    Never raises: a failure is logged and recorded on the run (`build_admission_error`); the next admission or Control
    Center poll releases the slot from the run's terminal record."""
    try:
        _build_admission.release(db, trace_id, reason=f"RUN_ENDED:{status_word}")
    except Exception as err:  # noqa: BLE001
        detail = f"{type(err).__name__}: {err}"
        logger.error(f"{_build_admission.BUILD_ADMISSION_UNAVAILABLE}: build slot of {trace_id} not released "
                     f"({detail})")
        try:
            run_ref.set({"build_admission_error": {"code": _build_admission.BUILD_ADMISSION_UNAVAILABLE,
                                                   "detail": detail[:500]}}, merge=True)
        except Exception as rec_err:  # noqa: BLE001 - the error log above stands
            logger.error(f"build_admission_error not stored on {trace_id} ({type(rec_err).__name__})")
        return
    _pump_queued_builds(db)


def _park_build_slot_and_pump(db: Any, run_ref: Any, trace_id: str, stage: str) -> None:
    """F2 option A: the run waits for a person (`stage`, an exact APPROVAL_WAIT_STAGES value): its slot is released and
    the next queued build dispatched. Never raises: a failure is logged and recorded on the run; the run then keeps
    its slot while it waits (the behaviour before option A), never more runs than the limit."""
    try:
        outcome = _build_admission.park(db, trace_id, stage=stage)
    except Exception as err:  # noqa: BLE001
        detail = f"{type(err).__name__}: {err}"
        logger.error(f"{_build_admission.BUILD_ADMISSION_UNAVAILABLE}: run {trace_id} keeps its build slot while it "
                     f"waits ({stage}): {detail}")
        try:
            run_ref.set({"build_admission_error": {"code": _build_admission.BUILD_ADMISSION_UNAVAILABLE,
                                                   "detail": detail[:500]}}, merge=True)
        except Exception as rec_err:  # noqa: BLE001
            logger.error(f"build_admission_error not stored on {trace_id} ({type(rec_err).__name__})")
        return
    if outcome == _build_admission.PARKED:
        _pump_queued_builds(db)


@app.post("/events/workflow-status")
def handle_workflow_status_update(req: WorkflowStatusUpdate):
    """
    Receives lifecycle telemetry events from Cloud Workflows or MCP agents
    and persists updates to Firestore pipeline_executions/{trace_id}.
    """
    project_id = os.getenv("PROJECT_ID", "")
    if not project_id or not req.trace_id:
        return {"status": "SKIPPED", "reason": "Missing project_id or trace_id"}

    try:
        from google.cloud import firestore
        db = firestore.Client(project=project_id)
        doc_ref = db.collection("pipeline_executions").document(req.trace_id)
        doc = doc_ref.get()
        stored_run = (doc.to_dict() or {}) if doc.exists else {}  # as stored before this event's own write

        update_payload: Dict[str, Any] = {}
        now_iso = datetime.now(timezone.utc).isoformat()

        if req.trace_id:
            update_payload["trace_id"] = req.trace_id
        if req.product_id:
            update_payload["product_id"] = req.product_id
        elif not doc.exists or not (doc.to_dict() or {}).get("product_id"):
            if req.trace_id and req.trace_id.startswith("intake-"):
                parts = req.trace_id.split("-")
                if len(parts) >= 2:
                    update_payload["product_id"] = parts[1]

        if not doc.exists or not (doc.to_dict() or {}).get("started_at"):
            update_payload["started_at"] = now_iso

        if req.status:
            update_payload["status"] = req.status
            if req.status in ["SUCCEEDED", "FAILED"]:
                update_payload["completed_at"] = now_iso
                if doc.exists:
                    d_dict = doc.to_dict() or {}
                    started_str = d_dict.get("started_at")
                    if started_str:
                        try:
                            st_dt = datetime.fromisoformat(started_str.replace("Z", "+00:00"))
                            update_payload["elapsed_seconds"] = round((datetime.now(timezone.utc) - st_dt).total_seconds(), 1)
                        except Exception:
                            pass

        if req.current_stage:
            update_payload["current_stage"] = req.current_stage

        if req.workflow_execution_id:
            update_payload["workflow_execution_id"] = req.workflow_execution_id

        # Update specific stage if provided
        if req.stage_name:
            st_data: Dict[str, Any] = {}
            if req.stage_status:
                st_data["status"] = req.stage_status
            if req.stage_summary:
                st_data["summary"] = _stage_summary(req.stage_name, req.stage_status, req.stage_summary)
            if st_data:
                update_payload.setdefault("stages", {})[req.stage_name] = st_data

        # Topological State Guardian: If any downstream stage has started, or workflow terminated, reconcile discovery
        downstream_stages = ["ARCHITECT", "COMPLIANCE", "FINOPS", "VENDING", "DEVELOPER", "GATEKEEPER", "QA", "TERRAFORM", "SRE", "COMPLETE"]
        is_past_discovery = (
            (req.current_stage and req.current_stage.upper() in downstream_stages)
            or (req.stage_name and req.stage_name.upper() in downstream_stages)
            or req.status in ["SUCCEEDED", "FAILED"]
        )

        if is_past_discovery:
            curr_discovery = (doc.to_dict() or {}).get("stages", {}).get("discovery", {})
            if "discovery" not in update_payload.get("stages", {}) and curr_discovery.get("status") in ["IN_FLIGHT", None]:
                update_payload.setdefault("stages", {})["discovery"] = {
                    "status": "SUCCESS",
                    "summary": curr_discovery.get("summary") or "GCP Org Policies harvested from folder & verified (0 LLM)"
                }

        if req.status == "SUCCEEDED":
            update_payload.setdefault("stages", {})["sre"] = {
                "status": "SKIPPED",
                "summary": SRE_IDLE_SUMMARY
            }

        outputs = {}
        if req.service_url:
            outputs["service_url"] = req.service_url
        if req.pull_request_url:
            outputs["pull_request_url"] = req.pull_request_url
        if req.state_file:
            outputs["state_file"] = req.state_file
        if outputs:
            update_payload["outputs"] = outputs

        if req.error_detail:
            update_payload["error"] = req.error_detail
        if req.error_class:
            update_payload["error_class"] = req.error_class
        if req.failed_stage:
            update_payload["failed_stage"] = req.failed_stage
        if req.reason:
            update_payload["failure_reason"] = req.reason

        if update_payload and _is_release_heartbeat(req.stage_name, req.stage_status):
            written = _write_release_heartbeat(db, doc_ref, update_payload)
            logger.info(f"Updated pipeline_executions for {req.trace_id}: {list(written.keys())}")
        elif update_payload:
            doc_ref.set(update_payload, merge=True)
            logger.info(f"Updated pipeline_executions for {req.trace_id}: {list(update_payload.keys())}")

        if req.status in ["SUCCEEDED", "FAILED"]:
            lock_pid = req.product_id or update_payload.get("product_id") or (
                (doc.to_dict() or {}).get("product_id") if doc.exists else None)
            _release_deployment_lock_for_trace(db, lock_pid, req.trace_id, req.status, now_iso)
            if req.status == "FAILED":
                _record_run_failure_on_workload(db, doc_ref, req.product_id or stored_run.get("product_id"), req.trace_id,
                                                update_payload.get("started_at") or stored_run.get("started_at"),
                                                req.error_class, req.error_detail)

        # Synchronize associated feature request in Firestore
        if req.status in ["SUCCEEDED", "FAILED"]:
            try:
                fr_status = "COMPLETED" if req.status == "SUCCEEDED" else "FAILED"
                req_id = None
                if doc.exists:
                    d_dict = doc.to_dict() or {}
                    req_id = d_dict.get("request_id")

                fr_update: Dict[str, Any] = {
                    "status": fr_status,
                    "completed_at": now_iso if req.status == "SUCCEEDED" else None,
                    "failed_at": now_iso if req.status == "FAILED" else None,
                }
                if req.service_url:
                    fr_update["service_url"] = req.service_url
                if req.error_detail:
                    fr_update["error"] = req.error_detail

                if req_id:
                    db.collection("feature_requests").document(req_id).set(fr_update, merge=True)
                    logger.info(f"Synchronized feature_request '{req_id}' to status '{fr_status}'")
                elif req.product_id:
                    active_frs = db.collection("feature_requests").where("product_id", "==", req.product_id).where("status", "in", ["IN_DEVELOPMENT", "IN_PROGRESS"]).stream()
                    for fr in active_frs:
                        db.collection("feature_requests").document(fr.id).set(fr_update, merge=True)
                        req_id = fr.id
                        logger.info(f"Synchronized feature_request '{fr.id}' to status '{fr_status}'")

                # Rollup token accounting to feature request and workload
                try:
                    from shared.token_accounting import rollup_tokens_to_feature
                    rollup_tokens_to_feature(db, req.trace_id, req_id, req.product_id)
                except Exception as t_err:
                    logger.debug(f"Token rollup notice for {req.trace_id}: {t_err}")
            except Exception as fr_err:
                logger.debug(f"Could not synchronize feature_requests status: {fr_err}")

        # BUILD-ADMISSION-QUEUE (RT F7): the ending run's records (run, workload, feature request) are final before its
        # build slot goes to the next queued run.
        if req.status in ["SUCCEEDED", "FAILED"]:
            _release_build_slot_and_pump(db, doc_ref, req.trace_id, req.status)
        elif req.current_stage in _build_admission.APPROVAL_WAIT_STAGES:
            # F2 option A (owner 11-14): a run that waits for a person gives its build slot to the next queued run; the
            # approval takes one again (Control Center approvals -> build_admission.resume) before the run goes on.
            _park_build_slot_and_pump(db, doc_ref, req.trace_id, req.current_stage)

        return {"status": "UPDATED", "trace_id": req.trace_id}
    except Exception as e:
        logger.warning(f"Could not update pipeline_executions for {req.trace_id}: {e}")
        return {"status": "ERROR", "error": str(e)}



if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
