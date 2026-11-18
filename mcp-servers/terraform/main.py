"""
Project Castor: Terraform MCP Tool Server
Exposes JSON-RPC 2.0 MCP tools and REST endpoints for deterministic Terraform lifecycle management.
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import hmac
import logging
import os
import sys
import threading
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator

try:
    from shared.callbacks import CallbackDeliveryClient, guaranteed_callback_scope
    from shared.logging_utils import AgentLifecycle
except ImportError:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
    from shared.callbacks import CallbackDeliveryClient, guaranteed_callback_scope
    from shared.logging_utils import AgentLifecycle

from service import TerraformService, IaCEngineDowngradeBlockedError, DestroyPolicy, ERROR_DESTROY_REQUIRES_APPROVAL
from service import SYNC_DEPLOY_TIME_BUDGET_S, deploy_url_summary
from service import SYNC_DEPLOY_RESPONSE_MARGIN_S, SYNC_REQUEST_LIMIT_S   # FD-7L 5b: the sync request's deadline
from service import install_runner_identity_mode   # FD-7L: the runner's one mode reader (2b F5 / FD-7L-F4)
from shared import runner_identity as ri   # FD-7L: the install's mode, read only through install_runner_identity_mode()
import runner_dispatch as rd               # FD-7L Phase 5a (SAT-31): dispatch through vending, route caller allow-list
import runner_runs as rr                   # FD-7L Phase 5b (SAT-31b): staged payloads + result channel (sync runs)
from shared.path_safety import (
    TF_WORKSPACE_RESERVED,
    UnsafePathError,
    validate_manifest_keys,
    validate_path_component,
    validate_trace_id,
)

logger = logging.getLogger("mcp-terraform-server")

app = FastAPI(
    title="StackVend Terraform MCP Tool Server",
    description="Model Context Protocol server for state-locked Terraform plan, apply, and drift checks on Google Cloud.",
    version="1.0.0",
)

service = TerraformService()

# Step 1 S1-B (register HS-03/HS-05/HS-52): POST /validate + GET /validate/ready for the developer stage's V1b.
# Authentication is the service's Cloud Run IAM (the gateway calls with an ID token, like every other route here).
from validate_service import ValidateService  # noqa: E402

validate_service = ValidateService(service.tooling_dir)

# FD-4AQ W3 (register AQ-5): a deploy's trace folder is deleted when the deploy ends; plan folders are kept for the
# /apply or /drift-check that follows and swept after TF_WORKSPACE_TTL_HOURS (24) unless a running request holds them.
from workspace_lifecycle import WorkspaceLifecycle  # noqa: E402

workspaces = WorkspaceLifecycle(service.workspace_root, service.workspace_trace_dir)


def _workspace_sweep_enabled() -> bool:
    # On Cloud Run (K_SERVICE set) by default; elsewhere (tests, local runs) only when explicitly enabled.
    return os.getenv("STACKVEND_WORKSPACE_SWEEP", "1" if os.getenv("K_SERVICE") else "0") == "1"


def _sweep_workspaces(force: bool = False) -> None:
    if not _workspace_sweep_enabled():
        return
    try:
        workspaces.sweep() if force else workspaces.maybe_sweep()
    except Exception as e:  # noqa: BLE001 - the sweep never fails a request
        logger.warning(f"WORKSPACE_SWEEP_FAILED: {type(e).__name__}: {e}")


@app.on_event("startup")
def _sweep_workspaces_at_startup() -> None:
    _sweep_workspaces(force=True)


@app.middleware("http")
async def _sweep_workspaces_before_request(request: Request, call_next):
    from starlette.concurrency import run_in_threadpool
    await run_in_threadpool(_sweep_workspaces)
    return await call_next(request)


@app.on_event("startup")
def _start_validate_warmup() -> None:
    """Background warm-up: verified engine binary (D12) + the full provider mirror, so /validate/ready turns true
    before the first developer dispatch asks (readiness before spend). Never blocks startup; failures show in
    /validate/ready. FD-4DM: /validate/ready answers not ready until this pass has finished (validate_service.py)."""
    # On Cloud Run (K_SERVICE set) by default; elsewhere (tests, local runs) only when explicitly enabled.
    if os.getenv("STACKVEND_VALIDATE_WARMUP", "1" if os.getenv("K_SERVICE") else "0") == "1":
        try:
            validate_service.start_warmup(service._ensure_provider_mirror)
        except Exception as e:  # noqa: BLE001 - never fails startup
            logger.warning(f"/validate warm-up not started: {type(e).__name__}: {e}")


@app.exception_handler(UnsafePathError)
async def _unsafe_path_handler(request: Request, exc: UnsafePathError):
    # FD-4G: request-, LLM- or repo-supplied key/ID failed structural path validation at a sink.
    logger.warning(f"Rejected unsafe path input on {request.url.path}: {exc.value!r} ({exc.reason})")
    return JSONResponse(status_code=400, content={"detail": f"unsafe path: {exc.reason}"})


# ------------------------------------------------------------------------------
# FD-4G request-boundary validators (422). The service layer re-validates for the MCP / applier paths.
# ------------------------------------------------------------------------------
def _check_hcl_files(v):
    if v is not None:
        validate_manifest_keys(v, reserved=TF_WORKSPACE_RESERVED)
    return v


def _check_trace_id(v):
    # FD-4G R-3: routes treat "" as absent (derived trace), so only validate non-empty values.
    if v:
        validate_trace_id(v)
    return v


def _check_product_id(v):
    validate_path_component(v)
    return v


# ------------------------------------------------------------------------------
# Request Models
# ------------------------------------------------------------------------------
class _PathSafeIds(BaseModel):
    @field_validator("product_id", check_fields=False)
    @classmethod
    def _v_product_id(cls, v):
        return _check_product_id(v)

    @field_validator("trace_id", check_fields=False)
    @classmethod
    def _v_trace_id(cls, v):
        return _check_trace_id(v)


class _PathSafeManifest(_PathSafeIds):
    @field_validator("hcl_files", check_fields=False)
    @classmethod
    def _v_hcl_files(cls, v):
        return _check_hcl_files(v)


class PlanRequest(_PathSafeManifest):
    product_id: str
    trace_id: Optional[str] = None
    hcl_files: Dict[str, str] = Field(description="Map of filenames to HCL content (e.g. main.tf, variables.tf)")
    iac_engine: Optional[str] = None


class ApplyRequest(_PathSafeIds):
    product_id: str
    trace_id: str
    iac_engine: Optional[str] = None


class DeployRequest(_PathSafeManifest):
    product_id: str
    trace_id: Optional[str] = None
    hcl_files: Optional[Dict[str, str]] = None
    target_project_id: Optional[str] = None
    branch: Optional[str] = None
    iac_engine: Optional[str] = None
    # EXP-7 (register row, owner 10-19): sent only by the Control Center's Express pipeline. refuse_destroy=true makes
    # every gated apply of this deploy refuse a plan that deletes or replaces a resource in state (tainted
    # replacements excepted) unless approved_removals equals exactly the addresses it removes. Absent = unchanged.
    refuse_destroy: bool = False
    approved_removals: Optional[List[str]] = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _approvals_need_refuse_destroy(self):
        if self.approved_removals and not self.refuse_destroy:
            raise ValueError("approved_removals is only valid with refuse_destroy=true (EXP-7, Express deploys)")
        return self


class AsyncDeployRequest(_PathSafeManifest):
    product_id: str
    trace_id: Optional[str] = None
    hcl_files: Optional[Dict[str, str]] = None
    target_project_id: Optional[str] = None
    branch: Optional[str] = None
    callback_url: str
    iac_engine: Optional[str] = None


class ValidateRequest(_PathSafeIds):
    files: Dict[str, str] = Field(description="Repo-keyed tree; only infra/ keys are validated")
    iac_engine: Optional[str] = "OPENTOFU"
    trace_id: Optional[str] = None

    @field_validator("files")
    @classmethod
    def _v_files(cls, v):
        validate_manifest_keys(v, reserved=TF_WORKSPACE_RESERVED)
        return v


class DriftCheckRequest(_PathSafeIds):
    product_id: str
    trace_id: str
    iac_engine: Optional[str] = None


class ForceUnlockRequest(BaseModel):
    product_id: str
    lock_id: str
    trace_id: Optional[str] = None
    iac_engine: Optional[str] = None

    # product_id may be "" here: /api/workloads/{product_id}/force-unlock falls back to the path parameter.
    # The service layer (_workspace_dir) validates whichever ID is finally used.
    @field_validator("product_id")
    @classmethod
    def _v_product_id(cls, v):
        return _check_product_id(v) if v else v

    @field_validator("trace_id")
    @classmethod
    def _v_trace_id(cls, v):
        return _check_trace_id(v) if v else v


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    method: str
    params: Optional[Dict[str, Any]] = Field(default_factory=dict)


# ------------------------------------------------------------------------------
# FD-7L Phase 5a (SAT-31; plan rev 3 sections 2.3, 2.12, 2.13). On a Shared install (mode unset / PLATFORM) nothing
# below reads a header, a token or a record: the routes behave as before. On a Per-workload install every workload
# route accepts only an allow-listed caller, and /deploy-async is dispatched through vending (one tf-applier execution
# per deploy, the nonce only in its environment); nothing credentialed runs in this container.
# ------------------------------------------------------------------------------
CALLER_TOKEN_VERIFIER = rd.verify_google_id_token   # replaced in tests; never bypassed by TEST_MODE
GUARD_DB_FACTORY = None                              # tests: a fake guard database (read only)
DISPATCH_CLIENT_FACTORY = rd.DispatchClient          # tests: a fake vending client
PROVENANCE_CERTS = ri.X509CertFetcher()             # Google's published certificates of the broker (cached)
_guard_db_client = None


def _runner_http_error(err: "ri.RunnerIdentityError", product_id: Optional[str] = None,
                       trace_id: Optional[str] = None) -> HTTPException:
    return HTTPException(status_code=err.http_status, detail=rd.refusal_detail(err, product_id, trace_id))


def _install_mode() -> str:
    """The install's runner identity mode, read ONLY through service.install_runner_identity_mode (the runner's one
    reader, which calls shared.runner_identity.runner_identity_mode; FD-7L-F4). An unknown value is refused (503 RUNNER_IDENTITY_MODE_INVALID): a misconfigured install never guesses a mode."""
    try:
        return install_runner_identity_mode()
    except ri.RunnerIdentityError as e:
        raise _runner_http_error(e)


def require_workload_caller(request: Request) -> None:
    """Plan 2.13 route caller allow-list, Per-workload installs only: a Google-signed ID token for this service from
    TF_SERVER_WORKLOAD_CALLERS (step A), else the workflow / gateway / Control Center / vending accounts of PROJECT_ID.
    401 / 403 / 503 with a typed code; the refusal is a security event. Shared install: returns at once."""
    if _install_mode() != ri.MODE_PER_WORKLOAD:
        return
    try:
        email = rd.authenticate_workload_caller(request.headers.get("authorization"), request.url.hostname,
                                                allowed=rd.workload_callers(os.environ),
                                                verifier=CALLER_TOKEN_VERIFIER)
    except ri.RunnerIdentityError as e:
        logger.warning(f"Workload route caller refused on {request.url.path}: {e.code}: {e.detail}",
                       extra={"security_event": "tf_server_workload_caller_refused", "refusal_code": e.code,
                              "http_status": e.http_status})
        headers = {"WWW-Authenticate": "Bearer"} if e.http_status == 401 else None
        raise HTTPException(status_code=e.http_status, detail={"code": e.code, "stage": e.stage, "detail": e.detail},
                            headers=headers)
    request.state.workload_caller = email


WORKLOAD_ROUTE = [Depends(require_workload_caller)]


def _guard_db():
    """The guard database (vending-signed provenance), read only. Plan step A sets its name on this server."""
    global _guard_db_client
    if GUARD_DB_FACTORY is not None:
        return GUARD_DB_FACTORY()
    if _guard_db_client is None:
        name = (os.getenv(rd.GUARD_DB_ENV) or "").strip()
        if not name:
            raise ri.RunnerIdentityError(rd.RUNNER_IDENTITY_NOT_READY, f"{rd.GUARD_DB_ENV} is not set on this server "
                                         "(plan step A)", stage="runner-config", http_status=503)
        from google.cloud import firestore
        _guard_db_client = firestore.Client(project=os.getenv("PROJECT_ID"), database=name)
    return _guard_db_client


# ------------------------------------------------------------------------------
# Health Check
# ------------------------------------------------------------------------------
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "mcp-terraform-server",
        "state_bucket": os.getenv("TFSTATE_BUCKET", ""),
        "environment": os.getenv("ENVIRONMENT", "prod"),
        "release": release_info.current_release(),  # FD-7C P3a: read-only, from this build's release.json
    }


# ------------------------------------------------------------------------------
# MCP Protocol Endpoint (JSON-RPC 2.0)
# ------------------------------------------------------------------------------
@app.post("/mcp", dependencies=WORKLOAD_ROUTE)
def handle_mcp_rpc(request: JsonRpcRequest):
    method = request.method
    params = request.params or {}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request.id,
            "result": {
                "tools": [
                    {
                        "name": "terraform_plan",
                        "description": (
                            "Runs init, validate and plan for the given HCL and saves the plan; never applies. "
                            "Reports adds, in-place changes and destroys; a replacement counts as a destroy. "
                            "is_safe_autonomous is false for any destroy/replacement or an unreadable plan. "
                            "Briefly takes the workload's state lock while planning."
                        ),
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "product_id": {"type": "string"},
                                "trace_id": {"type": "string"},
                                "hcl_files": {"type": "object", "description": "Map of filename to HCL code"},
                            },
                            "required": ["product_id", "hcl_files"],
                        },
                    },
                    {
                        "name": "terraform_drift_check",
                        "description": (
                            "Runs `plan -detailed-exitcode` in an existing plan workspace with the workload's IaC "
                            "engine: IN_SYNC (exit 0), DRIFT_DETECTED (exit 2) or ERROR (anything else). Never "
                            "applies. Briefly takes the workload's state lock."
                        ),
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "product_id": {"type": "string"},
                                "trace_id": {"type": "string"},
                            },
                            "required": ["product_id", "trace_id"],
                        },
                    },
                ]
            },
        }

    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        if tool_name == "terraform_drift_check":
            refusal = _unsupported_per_workload_run(f"MCP tool {tool_name}", arguments)
            if refusal is not None:   # FD-7L 5b: Per-workload only; a JSON-RPC error, like every tool failure
                return {"jsonrpc": "2.0", "id": request.id,
                        "error": {"code": -32000, "message": str(refusal), "data": rd.refusal_detail(refusal)}}
        if tool_name == "terraform_plan" and _install_mode() == ri.MODE_PER_WORKLOAD:
            return _mcp_plan_in_execution(request.id, arguments)   # FD-7L 5b part 2 (SAT-37)

        try:
            if tool_name == "terraform_plan":
                trace_id = arguments.get("trace_id", "auto-trace")
                with workspaces.hold(trace_id, delete_on_release=False):   # AQ-5: plan folders are kept (TTL)
                    result = service.generate_plan(
                        arguments["product_id"],
                        trace_id,
                        arguments["hcl_files"],
                        iac_engine=arguments.get("iac_engine"),
                    )
            elif tool_name == "terraform_drift_check":
                with workspaces.hold(arguments["trace_id"], delete_on_release=False):
                    result = service.check_drift(
                        arguments["product_id"],
                        arguments["trace_id"],
                        iac_engine=arguments.get("iac_engine"),
                    )
            else:
                # FD-4AO: terraform_apply and terraform_force_unlock are no longer agent tools. Applies run
                # through the pipeline; unlocks are an operator action on the REST endpoint.
                return {
                    "jsonrpc": "2.0",
                    "id": request.id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                }

            return {"jsonrpc": "2.0", "id": request.id, "result": {"content": [{"type": "text", "text": str(result)}]}}
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": request.id,
                "error": {"code": -32000, "message": str(e)},
            }

    return {
        "jsonrpc": "2.0",
        "id": request.id,
        "error": {"code": -32601, "message": f"Method '{method}' not supported."},
    }


# ------------------------------------------------------------------------------
# REST Endpoints
# ------------------------------------------------------------------------------
@app.post("/validate")
def validate_tree(req: ValidateRequest):
    """V1b: tofu init -backend=false + validate -json on a throw-away copy of the tree (no healers, no credentials,
    providers only from the mirror). Always 200 with status PASS | FAIL | UNAVAILABLE; UNAVAILABLE is never a pass."""
    return validate_service.validate(req.files, iac_engine=req.iac_engine, trace_id=req.trace_id or "")


@app.get("/validate/ready")
def validate_ready(iac_engine: str = "OPENTOFU"):
    # PROVIDER-CHECKSUMS: pinned providers the mirror left out (checksum mismatch / no pinned row / failed download).
    return dict(validate_service.ready(iac_engine), mirror_gaps=service.provider_mirror_gaps())


@app.post("/plan", dependencies=WORKLOAD_ROUTE)
def plan_infra(req: PlanRequest):
    if _install_mode() == ri.MODE_PER_WORKLOAD:   # FD-7L 5b part 2 (SAT-37): in a tf-applier execution
        try:
            return _plan_answer(_plan_in_execution(req.product_id, req.trace_id or "auto-trace", req.hcl_files,
                                                   req.iac_engine))
        except IaCEngineDowngradeBlockedError as de:
            raise HTTPException(status_code=400, detail=str(de))
        except _PlanRunFailed as e:
            raise HTTPException(status_code=500, detail=str(e))
    try:
        trace_id = req.trace_id or "auto-trace"
        with workspaces.hold(trace_id, delete_on_release=False):   # AQ-5: kept for /apply or /drift-check (TTL)
            return service.generate_plan(req.product_id, trace_id, req.hcl_files, iac_engine=req.iac_engine)
    except IaCEngineDowngradeBlockedError as de:
        raise HTTPException(status_code=400, detail=str(de))
    except UnsafePathError:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/apply", dependencies=WORKLOAD_ROUTE)
def apply_infra(req: ApplyRequest):
    _refuse_unsupported_per_workload_run("apply", req.product_id, req.trace_id)
    try:
        with workspaces.hold(req.trace_id, delete_on_release=False):
            res = service.apply_plan(req.product_id, req.trace_id, iac_engine=req.iac_engine)
        if res.get("status") == "REFUSED":
            # FD-4AO: only a saved, destroy-free plan is applied.
            raise HTTPException(status_code=409, detail=res)
        if res.get("status") == "FAILED":
            raise HTTPException(status_code=500, detail=f"Terraform apply failed: {res.get('stderr') or res.get('stdout')}")
        return res
    except IaCEngineDowngradeBlockedError as de:
        raise HTTPException(status_code=400, detail=str(de))
    except (HTTPException, UnsafePathError):
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def trigger_tf_applier_job(req: AsyncDeployRequest) -> bool:
    """
    Shared installs: delegates the deployment to one tf-applier Cloud Run Job execution.
    Returns True when the execution was started, False only when the job is switched off by configuration
    (ENABLE_TF_APPLIER_JOB=false: local runs and tests deploy in-process by design; Terraform sets it true).
    FD-7L Phase 5a (D3-a): a failed dispatch raises the typed TfApplierDispatchFailed; the deploy is never run
    in-process as a fallback. (Per-workload installs never come here: /deploy-async dispatches through vending.)
    """
    if os.getenv("ENABLE_TF_APPLIER_JOB", "true").lower() in ("false", "0", "no"):
        return False

    project_id = os.getenv("PROJECT_ID")
    region = os.getenv("REGION", "us-central1")
    job_name = os.getenv("TF_APPLIER_JOB_NAME", "tf-applier")
    if not project_id:
        raise rd.TfApplierDispatchFailed("PROJECT_ID_UNSET", "PROJECT_ID is not set on this server, so the "
                                         "tf-applier job cannot be named", http_status=503)

    env_overrides = [
        {"name": "PRODUCT_ID", "value": req.product_id},
        {"name": "TRACE_ID", "value": req.trace_id or f"deploy-async-{req.product_id}"},
        {"name": "BRANCH", "value": req.branch or "main"},
    ]
    if req.target_project_id:
        env_overrides.append({"name": "TARGET_PROJECT_ID", "value": req.target_project_id})
    if req.callback_url:
        env_overrides.append({"name": "CALLBACK_URL", "value": req.callback_url})
    if req.hcl_files:
        import json
        env_overrides.append({"name": "HCL_FILES_JSON", "value": json.dumps(req.hcl_files)})

    # Forward VCS and Serverless Git configuration to tf-applier container
    vcs_provider = os.getenv("VCS_PROVIDER")
    if vcs_provider:
        env_overrides.append({"name": "VCS_PROVIDER", "value": vcs_provider})

    git_server_url = os.getenv("GIT_SERVER_URL") or os.getenv("CASTOR_GIT_SERVER_URL")
    if git_server_url:
        env_overrides.append({"name": "GIT_SERVER_URL", "value": git_server_url})

    for vcs_key in ["GITHUB_MCP_URL", "GITHUB_ORG", "GITHUB_OWNER"]:
        val = os.getenv(vcs_key)
        if val:
            env_overrides.append({"name": vcs_key, "value": val})

    job_full_name = f"projects/{project_id}/locations/{region}/jobs/{job_name}"

    # 1. Primary Dispatch: Google Cloud Run SDK run_v2. SAT-31 RT M1: every failure is classified by type
    # (_classify_sdk_error): a refusal the API made itself (nothing started) may be retried (429 / 503 only) or handed
    # to the REST attempt; an ambiguous failure (the request may have started an execution) is never followed by
    # another RunJob.
    sdk_ready = False
    try:
        from google.cloud import run_v2
        client = run_v2.JobsClient()
        run_request = run_v2.RunJobRequest(
            name=job_full_name,
            overrides=run_v2.RunJobRequest.Overrides(
                container_overrides=[
                    run_v2.RunJobRequest.Overrides.ContainerOverride(env=env_overrides)
                ]
            ),
        )
        sdk_ready = True
    except ImportError:
        logger.info("google-cloud-run SDK not installed, using Cloud Run REST API dispatch")
    except Exception as e:  # noqa: BLE001 - nothing was sent (client or request not built)
        logger.warning(f"Could not prepare the run_v2 SDK dispatch ({type(e).__name__}: {e}); trying the REST API")
    if sdk_ready:
        for attempt in range(len(RUN_JOB_RETRY_DELAYS_S) + 1):
            try:
                operation = client.run_job(request=run_request)
                logger.info(f"Dispatched execution to Cloud Run Job '{job_full_name}' via run_v2 SDK [Operation: {operation.operation.name}]")
                return True
            except Exception as e:  # noqa: BLE001 - classified by type below
                sdk_err, kind = e, _classify_sdk_error(e)
            if kind == RUN_JOB_AMBIGUOUS:
                raise rd.TfApplierDispatchFailed(
                    "RUN_JOB_FAILED", f"the run_v2 SDK RunJob for '{job_name}' failed after it may have reached the "
                    f"Cloud Run Admin API ({type(sdk_err).__name__}); no second RunJob is sent", outcome_unknown=True)
            if kind == RUN_JOB_RETRY and attempt < len(RUN_JOB_RETRY_DELAYS_S):
                logger.warning(f"run_v2 SDK RunJob for '{job_name}' refused ({type(sdk_err).__name__}); retrying in "
                               f"{RUN_JOB_RETRY_DELAYS_S[attempt]:.0f} s")
                RUN_JOB_SLEEP(RUN_JOB_RETRY_DELAYS_S[attempt])
                continue
            if kind == RUN_JOB_RETRY:
                # SAT-31 re-check F1: the approved bound is 3 retries in all; the same quota is not retried again
                # through the REST transport.
                sdk_code = getattr(sdk_err, "code", None)
                raise rd.TfApplierDispatchFailed(
                    "RUN_JOB_FAILED", f"the Cloud Run Admin API refused the '{job_name}' RunJob "
                    f"({type(sdk_err).__name__}) {len(RUN_JOB_RETRY_DELAYS_S) + 1} times; nothing was started",
                    outcome_unknown=False, upstream_status=sdk_code if isinstance(sdk_code, int) else None)
            logger.warning(f"Could not dispatch via run_v2 SDK ({type(sdk_err).__name__}: {sdk_err}); the API refused "
                           "it (nothing started), attempting Cloud Run REST API fallback...")
            break

    # 2. Resilient Fallback: Google Cloud Run v2 REST API via google.auth + requests
    try:
        import google.auth
        from google.auth.transport.requests import Request as AuthRequest
        import requests

        credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        credentials.refresh(AuthRequest())
        token = credentials.token
    except Exception as auth_err:  # noqa: BLE001 - nothing was sent
        raise rd.TfApplierDispatchFailed("RUN_JOB_FAILED", f"no platform credentials for the Cloud Run Admin API "
                                         f"({type(auth_err).__name__}); nothing was started") from None

    url = f"https://run.googleapis.com/v2/projects/{project_id}/locations/{region}/jobs/{job_name}:run"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    body = {
        "overrides": {
            "containerOverrides": [
                {
                    "env": env_overrides
                }
            ]
        }
    }
    for attempt in range(len(RUN_JOB_RETRY_DELAYS_S) + 1):
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=30)
        except Exception as rest_err:  # noqa: BLE001
            unknown = not isinstance(rest_err, requests.exceptions.ConnectTimeout)
            logger.warning(f"REST API dispatch failed: {type(rest_err).__name__}: {rest_err}")
            raise rd.TfApplierDispatchFailed(
                "RUN_JOB_FAILED", f"the REST RunJob for '{job_name}' failed ({type(rest_err).__name__})"
                + ("; it may have reached the Cloud Run Admin API" if unknown else ""),
                outcome_unknown=unknown) from None
        if resp.status_code in (200, 202):
            op_data = resp.json()
            logger.info(f"Dispatched execution to Cloud Run Job '{job_name}' via REST API [HTTP {resp.status_code}, Operation: {op_data.get('name')}]")
            return True
        kind = _classify_rest_answer(resp)
        logger.warning(f"REST API dispatch for '{job_name}' returned HTTP {resp.status_code}: {resp.text}")
        if kind == RUN_JOB_RETRY and attempt < len(RUN_JOB_RETRY_DELAYS_S):
            RUN_JOB_SLEEP(RUN_JOB_RETRY_DELAYS_S[attempt])
            continue
        raise rd.TfApplierDispatchFailed(
            "RUN_JOB_FAILED", f"the Cloud Run Admin API did not start the '{job_name}' job (HTTP {resp.status_code})",
            outcome_unknown=kind == RUN_JOB_AMBIGUOUS, upstream_status=resp.status_code)
    raise AssertionError("unreachable")  # pragma: no cover - the loop always returns or raises


# SAT-31 RT M1: RunJob failure classes, decided by exception type, HTTP status and the API's own JSON status body
# (never message text).
RUN_JOB_RETRY = "RETRY"           # 429 / 503 refused by the API itself: nothing started, retried with backoff
RUN_JOB_REFUSED = "REFUSED"       # refused by the API (nothing started), not retried
RUN_JOB_AMBIGUOUS = "AMBIGUOUS"   # the request may have started an execution: never followed by another RunJob
RUN_JOB_RETRY_DELAYS_S = (2.0, 4.0, 8.0)   # at most 3 retries
_RETRY_API_STATUSES = {429: "RESOURCE_EXHAUSTED", 503: "UNAVAILABLE"}


def RUN_JOB_SLEEP(seconds: float) -> None:   # tests replace it
    import time
    time.sleep(seconds)


def _api_status(body: Any) -> Optional[str]:
    """`error.status` of the API's JSON status body ({"error": {"code", "message", "status"}}), else None."""
    err = body.get("error") if isinstance(body, dict) else None
    value = err.get("status") if isinstance(err, dict) else None
    return value if isinstance(value, str) and value else None


def _classify_rest_answer(resp: Any) -> str:
    try:
        api_status = _api_status(resp.json())
    except Exception:  # noqa: BLE001 - no JSON body
        api_status = None
    code = resp.status_code
    if api_status is not None:
        return RUN_JOB_RETRY if _RETRY_API_STATUSES.get(code) == api_status else RUN_JOB_REFUSED
    # No API status body: a front end answered. A 5xx (for example a gateway timeout) may hide a started execution.
    return RUN_JOB_AMBIGUOUS if not isinstance(code, int) or code >= 500 else RUN_JOB_REFUSED


def _classify_sdk_error(exc: Exception) -> str:
    try:
        from google.api_core import exceptions as gax
    except ImportError:  # pragma: no cover - the SDK depends on it
        return RUN_JOB_AMBIGUOUS
    if isinstance(exc, gax.TooManyRequests):               # incl. ResourceExhausted: a quota decision of the API
        return RUN_JOB_RETRY
    if isinstance(exc, gax.ServiceUnavailable):
        # Only with the API's own JSON status body (REST transport); a gRPC UNAVAILABLE may come after the send.
        response = getattr(exc, "response", None)
        try:
            api_status = _api_status(response.json()) if response is not None else None
        except Exception:  # noqa: BLE001
            api_status = None
        return RUN_JOB_RETRY if api_status == "UNAVAILABLE" else RUN_JOB_AMBIGUOUS
    if isinstance(exc, (gax.BadRequest, gax.Unauthorized, gax.Forbidden, gax.NotFound)):
        return RUN_JOB_REFUSED                             # InvalidArgument, FailedPrecondition, Unauthenticated, ...
    return RUN_JOB_AMBIGUOUS                               # DeadlineExceeded, Unknown, Internal, Aborted, Cancelled, ...


def _report_dispatch_failure(req: AsyncDeployRequest, trace_id: str, err: "rd.TfApplierDispatchFailed") -> None:
    """FD-7L Phase 5a: the workflow gets a typed FAILED callback (operator_required); nothing runs in-process."""
    logger.error(f"{err} for {req.product_id} [Trace: {trace_id}]; the deploy is not run in this container")
    with guaranteed_callback_scope(
        callback_url=req.callback_url,
        trace_id=trace_id,
        stage_name="terraform",
        product_id=req.product_id,
        firestore_db=service.db,
    ) as outcome:
        outcome.update(err.result(req.product_id, trace_id))


def run_deploy_in_background(req: AsyncDeployRequest):
    trace_id = req.trace_id or f"deploy-async-{req.product_id}"

    # FD-4G (T4): validate the (possibly derived) trace ID BEFORE dispatching the job or touching the
    # filesystem. A bad ID reports FAILED via the guaranteed callback instead of reaching rmtree.
    try:
        workspace_cleanup_dir = service.workspace_trace_dir(trace_id)
    except UnsafePathError:
        with guaranteed_callback_scope(
            callback_url=req.callback_url,
            trace_id=trace_id,
            stage_name="terraform",
            product_id=req.product_id,
            firestore_db=service.db,
        ):
            raise

    # Check if execution should be delegated to the dedicated tf-applier Cloud Run Job
    try:
        delegated = trigger_tf_applier_job(req)
    except rd.TfApplierDispatchFailed as dispatch_err:
        _report_dispatch_failure(req, trace_id, dispatch_err)
        return
    if delegated:
        logger.info(f"Deployment for {req.product_id} successfully delegated to tf-applier Cloud Run Job.")
        return

    # FD-4AQ W3 (AQ-5): the in-process deploy's trace folder (app source, .terraform, plan files) is deleted when
    # the deploy ends, however it ends, unless another running request holds the same trace ID.
    with workspaces.hold(trace_id, delete_on_release=True):
        _run_deploy_in_process(req, trace_id, workspace_cleanup_dir)


def _run_deploy_in_process(req: AsyncDeployRequest, trace_id: str, workspace_cleanup_dir: str) -> None:
    with AgentLifecycle("Terraform-Deploy", req.product_id, trace_id, mode="ASYNC CALLBACK") as agent:
        # Pre-flight workspace isolation: clean <workspace_root>/{trace_id} to avoid stale lock files
        if os.path.exists(workspace_cleanup_dir):
            try:
                import shutil
                shutil.rmtree(workspace_cleanup_dir, ignore_errors=True)
                logger.info(f"Cleaned pre-existing workspace directory at {workspace_cleanup_dir}")
            except Exception as ws_err:
                logger.debug(f"Workspace pre-clean notice: {ws_err}")

        with guaranteed_callback_scope(
            callback_url=req.callback_url,
            trace_id=trace_id,
            stage_name="terraform",
            product_id=req.product_id,
            firestore_db=service.db,
        ) as outcome:
            logger.info(f"Starting async Terraform deployment for {req.product_id} [Trace: {trace_id}]")
            res = service.deploy_workload(
                product_id=req.product_id,
                trace_id=trace_id,
                hcl_files=req.hcl_files,
                target_project_id=req.target_project_id,
                branch=req.branch,
            )
            res_status = res.get("status")
            if res_status != "SUCCESS":
                err_msg = res.get("error") or res.get("stderr") or res.get("stdout") or f"Terraform deployment failed with status {res_status}"
                agent.set_summary(f"Deployment failed: {err_msg[:120]}", status="FAILED")
                outcome["outputs"] = res
                outcome.update(res)
                # FD-4AI-c F1 / FD-4D-c-e: status and error are set AFTER outcome.update(res), so the result's own word
                # and its own "error" (even None) never override them. err_msg is the result's error when it has one.
                outcome["error"] = err_msg
                outcome["status"] = "FAILED"
            else:
                agent.set_summary(
                    f"Deployed successfully. URL: {deploy_url_summary(res)}",
                    status="SUCCESS",
                )
                outcome["outputs"] = res
                outcome.update(res)
                outcome["status"] = "SUCCESS"   # FD-4AI-c F1: after update(res)


def _record_terraform_in_flight(trace_id: Optional[str]) -> None:
    if service.db and trace_id:
        try:
            service.db.collection("pipeline_executions").document(trace_id).set({
                "current_stage": "TERRAFORM",
                "stages": {
                    "terraform": {
                        "status": "IN_FLIGHT",
                        "state": "AWAITING_CALLBACK",
                        "started_at": datetime.now(timezone.utc).isoformat(),
                        "summary": "Building container image via Cloud Buildpacks & deploying Cloud Run",
                    }
                }
            }, merge=True)
        except Exception as pe_err:
            logger.warning(f"Could not update pipeline_executions on deploy-async dispatch: {pe_err}")


# ------------------------------------------------------------------------------
# FD-7L Phase 5a dispatch watcher (owner 11-01, register "FD-7L-TF amendment: callback grant"): a Per-workload
# execution that ends or never starts without redeeming its nonce gets ONE typed FAILED callback from this server
# (runner_dispatch.DispatchWatcher). Driven by a timer per dispatch on the instance that dispatched it, and by a
# periodic sweep of every instance (any instance may report any watch; the Firestore claim makes it at most once).
# Shared installs: nothing is registered or scheduled; nothing is swept on one that never switched (SAT-41: after a
# switch back to Shared the sweep still drains the watches left from the Per-workload period).
# ------------------------------------------------------------------------------
WATCH_STORE_FACTORY = None                 # tests: a fake watch store
WATCH_CLOCK = None                         # tests: a fake clock (time.time otherwise)
WATCH_SWEEP_INTERVAL_S = 60.0
WATCH_LOCAL_LIMIT_S = 3600.0               # the dispatching instance re-checks for at most this long after due time
_watch_sweeper_started = False
_watch_lock = threading.Lock()


def _watch_clock() -> float:
    import time
    return (WATCH_CLOCK or time.time)()


def _report_failed_before_redeem(result: Dict[str, Any]) -> None:
    """The typed FAILED callback, with this server's own identity (shared.callbacks), to the callback URL of the
    SIGNED dispatch record; the pipeline record gets the same failure."""
    with guaranteed_callback_scope(
        callback_url=result["callback_url"],
        trace_id=result.get("trace_id"),
        stage_name="terraform",
        product_id=result.get("product_id"),
        firestore_db=service.db,
    ) as outcome:
        outcome.update({k: v for k, v in result.items() if k != "callback_url"})


def _dispatch_watcher() -> Optional["rd.DispatchWatcher"]:
    if WATCH_STORE_FACTORY is not None:
        store = WATCH_STORE_FACTORY()
    elif service.db is not None:
        store = rd.WatchStore(service.db)
    else:
        return None
    return rd.DispatchWatcher(store, guard_db=_guard_db, expected_signer=ri.expected_broker_email,
                              certs=lambda *a, **k: PROVENANCE_CERTS(*a, **k), report=_report_failed_before_redeem,
                              clock=_watch_clock)


def _start_timer(delay_s: float, fn, *args) -> None:
    timer = threading.Timer(max(0.0, delay_s), fn, args=args)
    timer.daemon = True
    timer.start()


WATCH_SCHEDULER = _start_timer             # tests: a recorder


def _run_watch(dispatch_id: str, local_deadline: float) -> None:
    """The dispatching instance's own check; re-armed while undecided, at most until `local_deadline`."""
    try:
        watcher = _dispatch_watcher()
        state = watcher.check(dispatch_id) if watcher is not None else rd.WATCHING
    except Exception as e:  # noqa: BLE001 - logged; the periodic sweep of every instance checks it again
        logger.error(f"runner watch {dispatch_id[:12]}: {type(e).__name__}; left to the periodic sweep")
        state = rd.WATCHING
    if state == rd.WATCHING and _watch_clock() + rd.WATCH_RETRY_S <= local_deadline:
        WATCH_SCHEDULER(rd.WATCH_RETRY_S, _run_watch, dispatch_id, local_deadline)


def _watch_dispatch(dispatched: Dict[str, Any], product_id: str, trace_id: str) -> None:
    dispatch_id = dispatched.get("dispatch_id")
    watcher = _dispatch_watcher()
    if watcher is None:
        logger.error(f"RUNNER_WATCH_NOT_RECORDED for {product_id} (trace {trace_id}): no Firestore client; only the "
                     "periodic sweep of another instance can report a failure before the redeem")
    else:
        watcher.register(dispatch_id=dispatch_id, execution=dispatched["execution"], product_id=product_id,
                         trace_id=trace_id)
    delay = ri.REDEEM_WINDOW_SECONDS + rd.WATCH_MARGIN_S + 1.0
    WATCH_SCHEDULER(delay, _run_watch, dispatch_id, _watch_clock() + delay + WATCH_LOCAL_LIMIT_S)
    _ensure_watch_sweeper()


def _sweep_dispatch_watches() -> None:
    """SAT-41 (pre-switch RT HIGH-2 (c)): not gated on the mode. Every decision comes from vending's signed dispatch
    records, and a switch back to Shared must still drain the watches of executions dispatched before it (one that
    then starts on the Shared path exits without a callback). A sweeper thread runs only where watches can exist
    (_install_may_hold_watches)."""
    try:
        watcher = _dispatch_watcher()
        if watcher is not None:
            watcher.sweep()
    except Exception as e:  # noqa: BLE001 - the next sweep runs again; never fails a request
        logger.error(f"runner watch sweep failed: {type(e).__name__}")


def _watch_sweep_loop() -> None:
    import time
    while True:
        time.sleep(WATCH_SWEEP_INTERVAL_S)
        _sweep_dispatch_watches()


def _ensure_watch_sweeper() -> None:
    """One periodic sweeper thread per instance (Cloud Run only by default: STACKVEND_RUNNER_WATCH_SWEEP)."""
    global _watch_sweeper_started
    if os.getenv("STACKVEND_RUNNER_WATCH_SWEEP", "1" if os.getenv("K_SERVICE") else "0") != "1":
        return
    with _watch_lock:
        if _watch_sweeper_started:
            return
        _watch_sweeper_started = True
    threading.Thread(target=_watch_sweep_loop, name="runner-watch-sweep", daemon=True).start()


def _install_may_hold_watches() -> bool:
    """SAT-41 HIGH-2 (c): False only for a Shared install whose mode was never switched (nothing was ever dispatched
    through vending, so there is nothing to sweep: unchanged). True on a Per-workload install, after any switch in
    Settings (a change entry exists: watches from a Per-workload period may still be pending after a switch back),
    and when the mode or the change log cannot be read (the sweep decides from signed records only)."""
    try:
        if install_runner_identity_mode() == ri.MODE_PER_WORKLOAD:
            return True
    except ri.RunnerIdentityError:
        return True
    if not (os.getenv(rd.GUARD_DB_ENV) or "").strip():
        return False
    try:
        return ri.any_mode_change(_guard_db())
    except Exception:  # noqa: BLE001 - unreadable: sweep (it only acts on signed records)
        return True


@app.on_event("startup")
def _start_watch_sweeper_on_per_workload_installs() -> None:
    if _install_may_hold_watches():
        _ensure_watch_sweeper()


def _dispatch_deploy_through_vending(req: AsyncDeployRequest) -> Dict[str, Any]:
    """FD-7L Phase 5a (plan 2.3, 2.12, 2.13; Per-workload installs). Vending signs the dispatch record, creates the
    single-use nonce and starts ONE tf-applier execution with only that nonce in its environment; the execution takes
    product, branch, project and callback URL from the signed records. This server never sees the nonce or a deployer
    token and never runs the deploy itself. Refusals answer before anything is recorded (typed, operator_required):
    caller-supplied hcl_files (RUNNER_MODE_UNSUPPORTED: staged payloads are Phase 5b), a target_project_id that is not
    the signed record's project (RUNNER_TARGET_MISMATCH and the record checks), a dispatch vending refused or that
    failed (TF_APPLIER_DISPATCH_FAILED, cause = vending's code). Synchronous on purpose: the workflow sees a refusal
    in the HTTP answer, so no callback right is needed on this server (plan step B gives it none)."""
    trace_id = req.trace_id or f"deploy-async-{req.product_id}"
    try:
        if req.hcl_files:
            raise ri.RunnerIdentityError(
                rd.RUNNER_MODE_UNSUPPORTED, "caller-supplied hcl_files reach a tf-applier execution only as a staged "
                "payload (FD-7L Phase 5b); a Per-workload deploy reads its Terraform from the workload's repository",
                stage=rd.DISPATCH_STAGE, http_status=422)
        if req.target_project_id is not None:
            rd.check_request_target(req.product_id, req.target_project_id,
                                    provenance=rd.read_provenance(_guard_db(), req.product_id),
                                    expected_signer=ri.expected_broker_email(), certs=PROVENANCE_CERTS)
        client = DISPATCH_CLIENT_FACTORY(os.getenv(rd.VENDING_URL_ENV))
        dispatched = client.dispatch(product_id=req.product_id, trace_id=trace_id, branch=req.branch or "main",
                                     callback_url=req.callback_url)
    except rd.TfApplierDispatchFailed as e:
        logger.error(f"{e} for {req.product_id} [Trace: {trace_id}]; nothing runs in this container")
        raise HTTPException(status_code=e.http_status, detail=e.result(req.product_id, trace_id))
    except ri.RunnerIdentityError as e:
        logger.error(f"{e.code} ({e.stage}) for {req.product_id} [Trace: {trace_id}]: {e.detail}")
        raise _runner_http_error(e, req.product_id, trace_id)
    execution = dispatched["execution"]
    logger.info(f"Deployment for {req.product_id} [Trace: {trace_id}] dispatched through vending to tf-applier "
                f"execution {execution}")
    _record_terraform_in_flight(req.trace_id)
    try:
        _watch_dispatch(dispatched, req.product_id, trace_id)
    except Exception as e:  # noqa: BLE001 - the execution runs already; the periodic sweep still covers the watch
        logger.error(f"RUNNER_WATCH_NOT_RECORDED for {req.product_id} (trace {trace_id}): {type(e).__name__}")
    return {
        "status": "ACCEPTED",
        "product_id": req.product_id,
        "trace_id": req.trace_id,
        "execution": execution,
        "message": "Terraform deployment dispatched to a tf-applier execution through vending. Workflow will resume "
                   "via callback.",
    }


@app.post("/deploy-async", status_code=status.HTTP_202_ACCEPTED, dependencies=WORKLOAD_ROUTE)
def deploy_infra_async(req: AsyncDeployRequest, background_tasks: BackgroundTasks):
    """
    Asynchronously deploys workload infrastructure via Terraform and notifies Cloud Workflows via callback.
    Returns HTTP 202 immediately to prevent orchestrator HTTP timeouts.
    FD-7L Phase 5a: on a Per-workload install the deploy is dispatched through vending before the answer (one
    tf-applier execution; a refusal is a typed HTTP error, never an in-process run).
    """
    if _install_mode() == ri.MODE_PER_WORKLOAD:
        return _dispatch_deploy_through_vending(req)

    _record_terraform_in_flight(req.trace_id)

    background_tasks.add_task(run_deploy_in_background, req)
    return {
        "status": "ACCEPTED",
        "product_id": req.product_id,
        "trace_id": req.trace_id,
        "message": "Terraform deployment dispatched to background worker. Workflow will resume via callback.",
    }


# ------------------------------------------------------------------------------
# FD-7L Phase 5b (SAT-31b; plan rev 3 section 2.12, D3-a). On a Per-workload install the synchronous routes that hold
# deployer credentials run in ONE tf-applier execution each, dispatched through vending: sync /deploy (Express, vending
# redeploy) and both force-unlock routes. The request's inputs are a staged payload (runner_runs; its sha256 is in the
# signed dispatch record), the answer comes from the execution's result document, polled until the request's deadline
# and used only when its sha256 is the fingerprint vending signed into the dispatch record (SAT-37); vending's
# /runner/dispatch-status ends the wait once the execution ended without an accepted result (SAT-37, RT L2).
# /plan and the MCP plan tool run as executions too (SAT-37; the saved plan is not kept). Saved-plan /apply,
# /drift-check and the MCP drift tool are refused (RUNNER_MODE_UNSUPPORTED) until they run as executions too (they
# need the workspace of an earlier run; see docs/handoff/sat-37-report.md). Shared installs: none of this is reached.
# ------------------------------------------------------------------------------
STAGER_FACTORY = rr.PayloadStager          # tests: a fake stager
RESULT_STORE_FACTORY = None                # tests: a fake result store
SYNC_CLOCK = None                          # tests: a fake clock (time.time otherwise)
SYNC_SLEEP = None                          # tests: a fake sleep (time.sleep otherwise)


def _sync_clock() -> float:
    import time
    return (SYNC_CLOCK or time.time)()


def _sync_sleep(seconds: float) -> None:
    import time
    (SYNC_SLEEP or time.sleep)(seconds)


def _unsupported_per_workload_run(what: str, arguments: Any) -> Optional[ri.RunnerIdentityError]:
    """Per-workload installs only: the typed refusal of a run that does not yet have its tf-applier execution form
    (nothing is written or run). Shared installs: None."""
    if _install_mode() != ri.MODE_PER_WORKLOAD:
        return None
    err = ri.RunnerIdentityError(
        rd.RUNNER_MODE_UNSUPPORTED, f"{what} runs on a Per-workload install only as a tf-applier execution, which "
        "this release does not build yet (it needs the workspace of an earlier run); nothing ran "
        "(docs/handoff/sat-37-report.md section 6)",
        stage=rd.DISPATCH_STAGE, http_status=422)
    args = arguments if isinstance(arguments, dict) else {}
    logger.error(f"{err.code} for {args.get('product_id')} [Trace: {args.get('trace_id')}]: {what}")
    return err


def _refuse_unsupported_per_workload_run(what: str, product_id: Any, trace_id: Any) -> None:
    """Per-workload installs only: a run that does not yet have its tf-applier execution form is refused before
    anything is written or run (typed 422, operator_required). Shared installs: returns at once."""
    err = _unsupported_per_workload_run(what, {"product_id": product_id, "trace_id": trace_id})
    if err is not None:
        raise _runner_http_error(err, product_id if isinstance(product_id, str) else None,
                                 trace_id if isinstance(trace_id, str) else None)


def _result_store():
    if RESULT_STORE_FACTORY is not None:
        return RESULT_STORE_FACTORY()
    if service.db is None:
        raise ri.RunnerIdentityError(rd.RUNNER_IDENTITY_NOT_READY, "this server has no Firestore client to read the "
                                     "execution's result", stage="runner-config", http_status=503)
    return rr.ResultStore(service.db)


def _redeem_failed_check(dispatch_id: str, execution: str, dispatched_at: float):
    """Once vending's redeem window has passed (with the watcher's margin), at most once a minute: when the SIGNED
    dispatch record is still not redeemed, the execution failed before it held any credential (it applied nothing):
    TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM, instead of waiting for the request's deadline. An unreadable record
    decides nothing (the wait goes on)."""
    state = {"next": dispatched_at + ri.REDEEM_WINDOW_SECONDS + rd.WATCH_MARGIN_S, "redeemed": False}

    def check() -> Optional[ri.RunnerIdentityError]:
        now = _sync_clock()
        if state["redeemed"] or now < state["next"]:
            return None
        state["next"] = now + rd.WATCH_RETRY_S
        try:
            rec = rd.read_signed_dispatch_record(_guard_db, dispatch_id, ri.expected_broker_email(),
                                                 lambda *a, **k: PROVENANCE_CERTS(*a, **k))
        except ri.RunnerIdentityError as e:
            logger.warning(f"runner result {dispatch_id[:12]}: dispatch record not checked ({e.code}); still waiting")
            return None
        if rec.get("redeemed") is not False:
            state["redeemed"] = True
            return None
        return ri.RunnerIdentityError(
            rd.TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM, f"tf-applier execution {execution} did not redeem its "
            f"dispatch within {ri.REDEEM_WINDOW_SECONDS} s (it ended, never started, or was refused before the redeem; "
            "see its log). It held no deployer credentials, so it applied nothing.", stage=rd.DISPATCH_STAGE,
            http_status=502)
    return check


def _result_confirmation(dispatch_id: str, execution: str):
    """The result document lives in the default database, so it is accepted only for a dispatch whose SIGNED record
    shows it was redeemed by exactly that execution AND carries the fingerprint (sha256 of `result_json`) that the
    execution had vending sign before it wrote the document (SAT-37; closes RT M1's residual: a default-database
    writer can no longer substitute the answer). An unreadable record, a not-yet-redeemed one, or one without a signed
    fingerprint yet is looked at again (until the deadline: a planted document never ends the request while the
    execution may still deploy); a missing, forged or rebound record, or a document whose sha256 is not the signed
    fingerprint, refuses the result (RUNNER_RESULT_MISMATCH)."""
    still_running = (f"tf-applier execution {execution} may still be running: check it and the workload's state "
                     "before a retry")
    logged = set()

    def _once(what: str, message: str) -> None:
        if what not in logged:
            logged.add(what)
            logger.warning(message)

    def confirm(fingerprint: str):
        try:
            rec = rd.read_signed_dispatch_record(_guard_db, dispatch_id, ri.expected_broker_email(),
                                                 lambda *a, **k: PROVENANCE_CERTS(*a, **k))
        except ri.RunnerIdentityError as e:
            if e.code == "RUNNER_RECORD_UNVERIFIABLE":
                logger.warning(f"runner result {dispatch_id[:12]}: dispatch record not readable now ({e.code})")
                return rr.RETRY
            return ri.RunnerIdentityError(rr.RUNNER_RESULT_MISMATCH, f"the dispatch record does not verify "
                                          f"({e.code}); the result document is not used; {still_running}",
                                          stage=rr.RESULT_STAGE, http_status=502)
        if rec.get("execution") != execution:
            return ri.RunnerIdentityError(rr.RUNNER_RESULT_MISMATCH, "vending's signed record binds this dispatch to "
                                          f"another execution; the result document is not used; {still_running}",
                                          stage=rr.RESULT_STAGE, http_status=502)
        if rec.get("redeemed") is not True:
            _once("unredeemed", f"runner result {dispatch_id[:12]}: a result document exists before the signed "
                  f"redeem of {execution}; not used, still waiting")
            return rr.RETRY
        signed = rec.get("result_sha256")
        if signed is None:
            _once("unsigned", f"runner result {dispatch_id[:12]}: a result document exists before vending signed "
                  f"{execution}'s result fingerprint; not used, still waiting")
            return rr.RETRY
        if not isinstance(signed, str) or not hmac.compare_digest(signed.encode("utf-8"),
                                                                  fingerprint.encode("utf-8")):
            return ri.RunnerIdentityError(
                rr.RUNNER_RESULT_MISMATCH, f"the result document's sha256 is not the fingerprint vending signed for "
                f"tf-applier execution {execution}; the document is not used. The execution reported its own result "
                "to vending, so it has finished or is finishing; its real outcome is in its log "
                f"({rr.RUNNER_RESULT_NOT_RECORDED}): check it and the workload's state before a retry",
                stage=rr.RESULT_STAGE, http_status=502)
        return None
    return confirm


def _execution_ended_check(dispatch_id: str, execution: str, dispatched_at: float):
    """RT L2 (SAT-37): from EXECUTION_STATE_FIRST_S after the dispatch, at most once a minute, ask vending whether the
    bound execution has ended. Once vending has reported it ended for EXECUTION_ENDED_GRACE_S and no accepted result
    appeared meanwhile, the wait ends: TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM when vending's record shows no redeem
    (it applied nothing), else TF_APPLIER_EXECUTION_ENDED_WITHOUT_RESULT (it may have applied: an operator checks).
    An answer vending cannot give, or one about another execution, decides nothing (the wait goes on)."""
    state = {"next": dispatched_at + rr.EXECUTION_STATE_FIRST_S, "ended_at": None, "logged": False}

    def check() -> Optional[ri.RunnerIdentityError]:
        now = _sync_clock()
        if now < state["next"]:
            return None
        state["next"] = now + rd.WATCH_RETRY_S
        try:
            seen = DISPATCH_CLIENT_FACTORY(os.getenv(rd.VENDING_URL_ENV)).execution_state(dispatch_id)
        except ri.RunnerIdentityError as e:
            if not state["logged"]:
                state["logged"] = True
                logger.warning(f"runner result {dispatch_id[:12]}: execution state not known ({e.code}); still "
                               "waiting")
            return None
        if seen.get("execution") != execution or seen.get("ended") is not True:
            state["ended_at"] = None
            return None
        if state["ended_at"] is None:
            state["ended_at"] = now
        if now - state["ended_at"] < rr.EXECUTION_ENDED_GRACE_S:
            return None
        counts = (f"succeeded {seen.get('succeeded_count')}, failed {seen.get('failed_count')}, cancelled "
                  f"{seen.get('cancelled_count')}")
        if seen.get("redeemed") is not True and _signed_record_unredeemed(dispatch_id):
            return ri.RunnerIdentityError(
                rd.TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM, f"tf-applier execution {execution} ended ({counts}) "
                "without redeeming its dispatch (see its log). It held no deployer credentials, so it applied "
                "nothing.", stage=rd.DISPATCH_STAGE, http_status=502)
        return ri.RunnerIdentityError(
            rr.TF_APPLIER_EXECUTION_ENDED_WITHOUT_RESULT, f"tf-applier execution {execution} ended ({counts}) "
            f"without a result this server could accept (result fingerprint signed: {seen.get('result_signed')}); "
            f"see its log ({rr.RUNNER_RESULT_NOT_RECORDED}). It held deployer credentials, so it may have applied "
            "changes: check the workload's state before a retry", stage=rr.RESULT_STAGE, http_status=502)
    return check


def _signed_record_unredeemed(dispatch_id: str) -> bool:
    """RT L2 (rt-sat-37): "it applied nothing" is decided only from vending's SIGNED record (redeemed is False), never
    from the status answer alone. Any read or verification failure -> False (the caller then uses the conservative
    TF_APPLIER_EXECUTION_ENDED_WITHOUT_RESULT)."""
    try:
        rec = rd.read_signed_dispatch_record(_guard_db, dispatch_id, ri.expected_broker_email(),
                                             lambda *a, **k: PROVENANCE_CERTS(*a, **k))
    except Exception as e:  # noqa: BLE001 - not verifiable now: never claim "applied nothing"
        logger.warning(f"runner result {dispatch_id[:12]}: signed record not read for the ended run "
                       f"({getattr(e, 'code', type(e).__name__)})")
        return False
    return rec.get("redeemed") is False


def _first_failure(*checks):
    """The wait's stop checks, in order; the first refusal ends the wait."""
    def check() -> Optional[ri.RunnerIdentityError]:
        for one in checks:
            failed = one()
            if failed is not None:
                return failed
        return None
    return check


def _run_in_execution(*, mode: str, product_id: str, trace_id: str, branch: str, target_project_id: Optional[str],
                      options: Dict[str, Any], started: float) -> Dict[str, Any]:
    """Stage the payload, dispatch ONE execution through vending (no callback URL: the result channel answers), wait
    for its result until the request's deadline. Every refusal is a typed HTTPException (operator_required); nothing
    credentialed runs in this container."""
    try:
        if not ri.expected_broker_email():   # RT L1: never a full-length wait on an unverifiable signer
            raise ri.RunnerIdentityError(rd.RUNNER_IDENTITY_NOT_READY, "the broker identity (STACKVEND_BROKER_SA) is "
                                         "not configured on this server (plan step A); nothing was dispatched",
                                         stage="runner-config", http_status=503)
        if target_project_id is not None:
            rd.check_request_target(product_id, target_project_id,
                                    provenance=rd.read_provenance(_guard_db(), product_id),
                                    expected_signer=ri.expected_broker_email(), certs=PROVENANCE_CERTS)
        store = _result_store()
        stager = STAGER_FACTORY(rr.staging_bucket(os.environ))
        client = DISPATCH_CLIENT_FACTORY(os.getenv(rd.VENDING_URL_ENV))
        data = rr.build_payload(mode=mode, product_id=product_id, trace_id=trace_id, options=options)
        payload_ref, payload_sha256 = stager.stage(product_id=product_id, trace_id=trace_id, data=data)
        dispatched = client.dispatch(product_id=product_id, trace_id=trace_id, branch=branch, callback_url=None,
                                     mode=mode, payload_ref=payload_ref, payload_sha256=payload_sha256)
    except rd.TfApplierDispatchFailed as e:
        logger.error(f"{e} for {product_id} [Trace: {trace_id}]; nothing runs in this container")
        raise HTTPException(status_code=e.http_status, detail=e.result(product_id, trace_id))
    except ri.RunnerIdentityError as e:
        logger.error(f"{e.code} ({e.stage}) for {product_id} [Trace: {trace_id}]: {e.detail}")
        raise _runner_http_error(e, product_id, trace_id)
    execution, dispatch_id = dispatched["execution"], dispatched["dispatch_id"]
    logger.info(f"{mode} of {product_id} [Trace: {trace_id}] dispatched through vending to tf-applier execution "
                f"{execution}; waiting for its result")
    dispatched_at = _sync_clock()
    try:
        return rr.wait_for_result(
            store, dispatch_id=dispatch_id,
            expected={"execution": execution, "product_id": product_id, "trace_id": trace_id, "mode": mode},
            deadline=started + SYNC_REQUEST_LIMIT_S - SYNC_DEPLOY_RESPONSE_MARGIN_S, clock=_sync_clock,
            sleep=_sync_sleep,
            redeem_failed=_first_failure(_redeem_failed_check(dispatch_id, execution, dispatched_at),
                                         _execution_ended_check(dispatch_id, execution, dispatched_at)),
            confirm=_result_confirmation(dispatch_id, execution))
    except ri.RunnerIdentityError as e:
        logger.error(f"{e.code} ({e.stage}) for {product_id} [Trace: {trace_id}, execution {execution}]: {e.detail}")
        raise _runner_http_error(e, product_id, trace_id)


def _deploy_in_execution(req: DeployRequest, trace_id: str):
    """Sync /deploy on a Per-workload install. The execution gets the request's deadline (DEPLOY-SYNC-BUDGET: the
    deploy budget from the moment this request started) and runs with the server's per-command limits; the answer is
    built from its result exactly as an in-process sync deploy's (_deploy_answer)."""
    started = _sync_clock()
    destroy_policy = DestroyPolicy(frozenset(req.approved_removals or ())) if req.refuse_destroy else None
    options = {"hcl_files": req.hcl_files, "iac_engine": req.iac_engine, "refuse_destroy": req.refuse_destroy,
               "approved_removals": list(req.approved_removals) if req.approved_removals is not None else None,
               "deadline_epoch": started + SYNC_DEPLOY_TIME_BUDGET_S - rr.SYNC_RESULT_MARGIN_S}   # RT M2
    with AgentLifecycle("Terraform-Deploy", req.product_id, trace_id, mode="SYNC") as agent:
        try:
            res = _run_in_execution(mode="deploy", product_id=req.product_id, trace_id=trace_id,
                                    branch=req.branch or "main", target_project_id=req.target_project_id,
                                    options=options, started=started)
        except HTTPException as e:
            code = e.detail.get("error_class") if isinstance(e.detail, dict) else None
            agent.set_summary(f"Deployment refused: {code}", status="FAILED")
            raise
        return _deploy_answer(res, destroy_policy, agent)


def _force_unlock_in_execution(product_id: str, req: ForceUnlockRequest) -> Dict[str, Any]:
    """Both force-unlock routes on a Per-workload install: the unlock (with its lock checks, service.force_unlock)
    runs in a tf-applier execution with the workload deployer's credentials; the answer keeps the routes' shape."""
    started = _sync_clock()
    trace_id = req.trace_id or f"force-unlock-{product_id}-{int(started)}"
    res = _run_in_execution(mode="force_unlock", product_id=product_id, trace_id=trace_id, branch="main",
                            target_project_id=None, options={"lock_id": req.lock_id, "iac_engine": req.iac_engine},
                            started=started)
    if res.get("status") == "FAILED":
        raise HTTPException(status_code=500, detail=res.get("error", "Force-unlock failed"))
    return res


class _PlanRunFailed(Exception):
    """The plan execution ended with an untyped failure (in-process: an exception, HTTP 500 / JSON-RPC -32000)."""


def _plan_in_execution(product_id: str, trace_id: str, hcl_files: Any, iac_engine: Optional[str]) -> Dict[str, Any]:
    """FD-7L 5b part 2 (SAT-37): /plan and the MCP plan tool on a Per-workload install. service.generate_plan runs
    unchanged in ONE tf-applier execution (staged payload: the files and the engine; the request's budget as its
    start deadline) with the workload deployer's credentials. Its saved plan stays in that execution and is deleted
    with it, so the answer says `saved_plan_kept: false` (saved-plan apply is not an execution yet)."""
    started = _sync_clock()
    options = {"hcl_files": hcl_files, "iac_engine": iac_engine,
               "deadline_epoch": started + SYNC_DEPLOY_TIME_BUDGET_S - rr.SYNC_RESULT_MARGIN_S}
    return _run_in_execution(mode="plan", product_id=product_id, trace_id=trace_id, branch="main",
                             target_project_id=None, options=options, started=started)


def _plan_answer(res: Dict[str, Any]) -> Dict[str, Any]:
    """The in-process /plan answer for an execution's plan result: the result dict (any plan status, typed refusals
    included, as generate_plan returns them), IaCEngineDowngradeBlockedError for the engine gate (HTTP 400),
    _PlanRunFailed for an untyped failure (HTTP 500)."""
    if res.get("error_class") == rr.IAC_ENGINE_DOWNGRADE_BLOCKED:
        raise IaCEngineDowngradeBlockedError(res.get("error") or rr.IAC_ENGINE_DOWNGRADE_BLOCKED)
    if res.get("status") == "FAILED" and not res.get("error_class"):
        raise _PlanRunFailed(res.get("error") or "the plan execution failed")
    return dict(res, saved_plan_kept=False)


def _mcp_plan_in_execution(request_id: Any, arguments: Any) -> Dict[str, Any]:
    """The MCP terraform_plan tool on a Per-workload install: the same execution as /plan, in the tool's answer form
    (the result as text; every failure a JSON-RPC -32000 error, a typed refusal with its detail as `data`)."""
    try:
        if not isinstance(arguments, dict):
            raise TypeError("arguments is not an object")
        product_id, hcl_files = arguments["product_id"], arguments["hcl_files"]
        _check_product_id(product_id)
        if not isinstance(hcl_files, dict):          # RT L1 (rt-sat-37): /plan's PlanRequest checks, before staging
            raise TypeError("hcl_files is not an object")
        _check_hcl_files(hcl_files)
        result = _plan_answer(_plan_in_execution(product_id, arguments.get("trace_id", "auto-trace"),
                                                 hcl_files, arguments.get("iac_engine")))
    except HTTPException as e:
        detail = e.detail if isinstance(e.detail, dict) else None
        error = {"code": -32000, "message": (detail or {}).get("error") or str(e.detail)}
        if detail is not None:
            error["data"] = detail
        return {"jsonrpc": "2.0", "id": request_id, "error": error}
    except Exception as e:  # noqa: BLE001 - the tool's in-process contract: every failure is -32000
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": str(e)}}
    return {"jsonrpc": "2.0", "id": request_id, "result": {"content": [{"type": "text", "text": str(result)}]}}


@app.post("/deploy", dependencies=WORKLOAD_ROUTE)
def deploy_infra(req: DeployRequest):
    """Executes single-pass end-to-end Terraform initialization and apply with GCS state locking.
    FD-7L Phase 5b: on a Per-workload install the deploy runs in ONE tf-applier execution dispatched through vending
    (staged payload + result channel); the answer has the same shape."""
    trace_id = req.trace_id or "auto-deploy"
    if _install_mode() == ri.MODE_PER_WORKLOAD:
        return _deploy_in_execution(req, trace_id)
    # FD-4AQ W3 (AQ-5): the deploy's trace folder is deleted when the request ends (success, failure, exception).
    with workspaces.hold(trace_id, delete_on_release=True):
        return _deploy_sync(req, trace_id)


def _deploy_sync(req: DeployRequest, trace_id: str):
    destroy_policy = DestroyPolicy(frozenset(req.approved_removals or ())) if req.refuse_destroy else None
    with AgentLifecycle("Terraform-Deploy", req.product_id, trace_id, mode="SYNC") as agent:
        try:
            res = service.deploy_workload(
                product_id=req.product_id,
                trace_id=trace_id,
                hcl_files=req.hcl_files,
                target_project_id=req.target_project_id,
                branch=req.branch,
                iac_engine=req.iac_engine,
                destroy_policy=destroy_policy,
                time_budget_s=SYNC_DEPLOY_TIME_BUDGET_S,   # DEPLOY-SYNC-BUDGET: one deadline for the whole request
            )
            return _deploy_answer(res, destroy_policy, agent)
        except HTTPException:
            raise
        except UnsafePathError as e:
            agent.set_summary(f"Deployment rejected: {e.reason}", status="FAILED")
            raise
        except Exception as e:
            agent.set_summary(f"Deployment exception: {str(e)}", status="FAILED")
            raise HTTPException(status_code=500, detail=str(e))


def _deploy_answer(res: Dict[str, Any], destroy_policy: Optional[DestroyPolicy], agent: Any) -> Dict[str, Any]:
    """The sync /deploy answer for a deploy result (in-process or, FD-7L 5b, from a tf-applier execution): the result
    on SUCCESS, else the typed HTTP error (moved unchanged out of _deploy_sync)."""
    if destroy_policy is not None and res.get("error_class") == ERROR_DESTROY_REQUIRES_APPROVAL:
        # EXP-7: a typed 409 the Express pipeline reads (never parsed out of an error string)
        agent.set_summary(f"Deployment refused: {ERROR_DESTROY_REQUIRES_APPROVAL}", status="FAILED")
        raise HTTPException(status_code=409, detail={
            k: res.get(k) for k in ("error_class", "error", "removal_addresses", "destroy_requires_approval",
                                    "approved_removals")})
    res_status = res.get("status")
    if res_status != "SUCCESS":
        err_msg = res.get("error") or res.get("stderr") or res.get("stdout") or f"Terraform deployment failed with status {res_status}"
        agent.set_summary(f"Deployment failed: {err_msg[:120]}", status="FAILED")
        if destroy_policy is not None:
            # EXP-8: an Express deploy gets the result's own typed error_class (DESTROY_BLOCKED, COMPLIANCE_*,
            # STATE_LOCKED, ...; None when the result has none) so the pipeline records a typed reason.
            # Agent-mode deploys (no policy) keep the string detail unchanged.
            res_class = res.get("error_class")
            raise HTTPException(status_code=500, detail={
                "error_class": res_class if isinstance(res_class, str) and res_class else None,
                "error": f"Terraform deployment failed: {err_msg}"})
        raise HTTPException(status_code=500, detail=f"Terraform deployment failed: {err_msg}")
    agent.set_summary(f"Deployed successfully. URL: {deploy_url_summary(res)}", status="SUCCESS")
    return res


@app.post("/drift-check", dependencies=WORKLOAD_ROUTE)
def drift_check(req: DriftCheckRequest):
    _refuse_unsupported_per_workload_run("drift", req.product_id, req.trace_id)
    try:
        with workspaces.hold(req.trace_id, delete_on_release=False):
            res = service.check_drift(req.product_id, req.trace_id, iac_engine=req.iac_engine)
    except UnsafePathError:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    if res.get("status") == "ERROR":
        # FD-4AO: a failed drift check is an error, never "in sync".
        raise HTTPException(status_code=500, detail=res)
    return res


@app.post("/force-unlock", dependencies=WORKLOAD_ROUTE)
def force_unlock_state(req: ForceUnlockRequest):
    """Force-unlocks a stuck Terraform GCS state lock for a workload."""
    try:
        if _install_mode() == ri.MODE_PER_WORKLOAD:   # FD-7L 5b: in a tf-applier execution
            _check_product_id(req.product_id)
            return _force_unlock_in_execution(req.product_id, req)
        res = service.force_unlock(product_id=req.product_id, lock_id=req.lock_id, trace_id=req.trace_id, iac_engine=req.iac_engine)
        if res.get("status") == "FAILED":
            raise HTTPException(status_code=500, detail=res.get("error", "Force-unlock failed"))
        return res
    except (HTTPException, UnsafePathError):
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/workloads/{product_id}/force-unlock", dependencies=WORKLOAD_ROUTE)
def force_unlock_workload_state(product_id: str, req: ForceUnlockRequest):
    """Operator endpoint to force-unlock a stuck Terraform state lock for a specific workload."""
    # Red-team F-7: validate the path product_id at the boundary (UnsafePathError -> 400 via the handler).
    _check_product_id(product_id)
    # FD23-17: the path names the workload; a different body product_id must never redirect the unlock.
    if req.product_id and req.product_id != product_id:
        raise HTTPException(
            status_code=400,
            detail=f"product_id in the request body ('{req.product_id}') does not match the path ('{product_id}').",
        )
    try:
        if _install_mode() == ri.MODE_PER_WORKLOAD:   # FD-7L 5b: in a tf-applier execution
            return _force_unlock_in_execution(product_id, req)
        target_pid = product_id
        res = service.force_unlock(product_id=target_pid, lock_id=req.lock_id, trace_id=req.trace_id, iac_engine=req.iac_engine)
        if res.get("status") == "FAILED":
            raise HTTPException(status_code=500, detail=res.get("error", "Force-unlock failed"))
        return res
    except (HTTPException, UnsafePathError):
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
