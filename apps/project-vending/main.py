"""
Project Castor: Project & Repository Vending Service API
FastAPI microservice for provisioning GCP child projects, linking billing, and minting GitHub App JIT tokens.
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import logging
import os
import sys
import traceback
from typing import Any, Dict, List, Literal, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Header, Query, Request, status
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StrictBool, StrictInt

try:
    from shared.callbacks import CallbackDeliveryClient, guaranteed_callback_scope
    from shared.logging_utils import AgentLifecycle
except ImportError:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
    from shared.callbacks import CallbackDeliveryClient, guaranteed_callback_scope
    from shared.logging_utils import AgentLifecycle

from vending import (GITHUB_REPOSITORY_IDENTITY_FIELD, REDEPLOY_FAILURE_HTTP_STATUS, WORKLOAD_RECORD_UNREADABLE,
                     GitHubOwnerNotOrganizationError, GitHubRepositoryCreateError, ProjectRepoVendingEngine,
                     VendingFailure)
import cc_log_reader as ccl
import destructive_guard as dg
import managed_tag_backfill as mtb
import mcp_approvals
import runner_broker as rb

logger = logging.getLogger("project-repo-vending-api")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="StackVend Project & Repository Vending Service",
    description="Automates GCP child project creation under organization folders, billing linking, and GitHub App JIT token minting.",
    version="1.0.0",
)

vending_engine = ProjectRepoVendingEngine()

# Caller authentication for destructive routes (lane 18 S1, U1). Replaced in tests; never bypassed by TEST_MODE.
CALLER_TOKEN_VERIFIER = dg.verify_google_id_token


def verify_destructive_caller(authorization: Optional[str] = Header(None)) -> str:
    """Google-signed OIDC ID token, audience = VENDING_SERVICE_URL, email exactly in DESTRUCTIVE_CALLERS.
    Unconfigured -> 503; missing/invalid token -> 401; other identity -> 403."""
    callers, audiences = dg.caller_config_from_env()
    try:
        return dg.authenticate_caller(authorization, allowed=callers, audiences=audiences,
                                      verifier=CALLER_TOKEN_VERIFIER)
    except dg.CallerRefused as e:
        logger.warning(f"Destructive route caller refused: {e.code}: {e.detail}")
        headers = {"WWW-Authenticate": "Bearer"} if e.http_status == 401 else None
        raise HTTPException(status_code=e.http_status, detail={"code": e.code, "detail": e.detail}, headers=headers)


def verify_decommission_caller(authorization: Optional[str] = Header(None)) -> str:
    """C10 (RT finding 1): POST /projects/{id}/decommission ONLY. The caller is in DESTRUCTIVE_CALLERS (the Control
    Center) or in SANDBOX_TTL_CALLERS (+ the sandbox-workload-sweeper-job persona); a caller that is only in
    SANDBOX_TTL_CALLERS may request action_class SANDBOX_TTL and nothing else (checked in the route). Every other
    destructive-class route keeps verify_destructive_caller (DESTRUCTIVE_CALLERS only)."""
    destructive, audiences = dg.caller_config_from_env()
    ttl = dg.sandbox_ttl_callers_from_env()
    try:
        return dg.authenticate_caller(authorization, allowed=destructive | ttl, audiences=audiences,
                                      verifier=CALLER_TOKEN_VERIFIER,
                                      callers_env="DESTRUCTIVE_CALLERS / SANDBOX_TTL_CALLERS",
                                      caller_kind="decommission caller")
    except dg.CallerRefused as e:
        logger.warning(f"Decommission caller refused: {e.code}: {e.detail}")
        headers = {"WWW-Authenticate": "Bearer"} if e.http_status == 401 else None
        raise HTTPException(status_code=e.http_status, detail={"code": e.code, "detail": e.detail}, headers=headers)


def verify_github_token_caller(authorization: Optional[str] = Header(None)) -> str:
    """GH-TOKEN-CALLERS: GET /github-token answers only an exact allow-list (GITHUB_TOKEN_ALLOWED_CALLERS, default the
    refactor scanner's runtime SA). Same verifier as the destructive routes: Google-signed ID token, audience =
    VENDING_SERVICE_URL. Unconfigured -> 503; missing/invalid token -> 401; other identity -> 403. The refusal is a
    security event; the Authorization header and any GitHub token are never logged."""
    callers, audiences = dg.github_token_caller_config_from_env()
    try:
        return dg.authenticate_caller(authorization, allowed=callers, audiences=audiences,
                                      verifier=CALLER_TOKEN_VERIFIER, callers_env=dg.GITHUB_TOKEN_CALLERS_ENV,
                                      caller_kind="GitHub token caller")
    except dg.CallerRefused as e:
        logger.warning(f"GitHub token caller refused: {e.code}: {e.detail}",
                       extra={"security_event": "github_token_caller_refused", "refusal_code": e.code,
                              "http_status": e.http_status})
        headers = {"WWW-Authenticate": "Bearer"} if e.http_status == 401 else None
        raise HTTPException(status_code=e.http_status,
                            detail={"code": e.code, "stage": "github-token", "detail": e.detail}, headers=headers)


def verify_mcp_approval_consumer(authorization: Optional[str] = Header(None)) -> str:
    """APPROVAL-CONSUME-VIA-VENDING: POST /approvals/{id}/consume answers only an exact allow-list
    (MCP_APPROVAL_CONSUMERS, default the MCP servers' runtime SA). Same verifier as the destructive routes:
    Google-signed ID token, audience = VENDING_SERVICE_URL. Unconfigured -> 503; missing/invalid token -> 401;
    other identity -> 403."""
    callers, audiences = mcp_approvals.consumer_config_from_env()
    try:
        return dg.authenticate_caller(authorization, allowed=callers, audiences=audiences,
                                      verifier=CALLER_TOKEN_VERIFIER, callers_env=mcp_approvals.CONSUMERS_ENV,
                                      caller_kind="MCP approval consumer")
    except dg.CallerRefused as e:
        logger.warning(f"MCP approval consumer refused: {e.code}: {e.detail}",
                       extra={"security_event": "mcp_approval_consumer_refused", "refusal_code": e.code,
                              "http_status": e.http_status})
        headers = {"WWW-Authenticate": "Bearer"} if e.http_status == 401 else None
        raise HTTPException(status_code=e.http_status,
                            detail={"code": e.code, "stage": "approval-consume", "detail": e.detail}, headers=headers)


def _runner_caller(authorization: Optional[str], allowed, env_name: str, kind: str) -> str:
    """FD-7L broker routes: Google-signed ID token, audience = VENDING_SERVICE_URL, email exactly in `allowed`
    (the Terraform-owned STACKVEND_TF_RUNNER_MEMBERS / STACKVEND_TF_SERVER_MEMBERS; before step A, the existing
    STACKVEND_CHILD_PROJECT_OWNER_MEMBERS service accounts). Unconfigured -> 503; missing token -> 401; other -> 403."""
    _, audiences = dg.caller_config_from_env()
    try:
        return dg.authenticate_caller(authorization, allowed=allowed, audiences=audiences,
                                      verifier=CALLER_TOKEN_VERIFIER, callers_env=env_name, caller_kind=kind)
    except dg.CallerRefused as e:
        logger.warning(f"Runner broker caller refused: {e.code}: {e.detail}",
                       extra={"security_event": "runner_broker_caller_refused", "refusal_code": e.code,
                              "http_status": e.http_status})
        headers = {"WWW-Authenticate": "Bearer"} if e.http_status == 401 else None
        raise HTTPException(status_code=e.http_status,
                            detail={"code": e.code, "stage": "runner-broker", "detail": e.detail}, headers=headers)


def _runner_deps():
    try:
        return vending_engine.runner_deps
    except rb.ri.RunnerIdentityError as e:   # an unknown STACKVEND_TF_RUNNER_IDENTITY value
        raise _runner_http_error(e)


# RT F6: the caller checks read only the environment (no engine dependencies, no clients, no mode parse) before the
# caller is authenticated; the broker's dependencies are built after the check passed.
def verify_runner_job_caller(authorization: Optional[str] = Header(None)) -> str:
    return _runner_caller(authorization, rb.BrokerConfig.members_from_env(rb.ri.RUNNER_MEMBERS_ENV),
                          rb.ri.RUNNER_MEMBERS_ENV, "tf-applier runner")


def verify_runner_server_caller(authorization: Optional[str] = Header(None)) -> str:
    return _runner_caller(authorization, rb.BrokerConfig.members_from_env(rb.ri.SERVER_MEMBERS_ENV),
                          rb.ri.SERVER_MEMBERS_ENV, "terraform server")


def _runner_http_error(err: "rb.RunnerIdentityError") -> HTTPException:
    return HTTPException(status_code=err.http_status,
                         detail={"code": err.code, "stage": err.stage, "detail": err.detail})


def _guard_http_error(err: Exception) -> HTTPException:
    if isinstance(err, dg.DeletionRefused):
        return HTTPException(status_code=err.http_status, detail={"code": err.code, "detail": err.detail})
    if isinstance(err, dg.DecommissionFailed):
        return HTTPException(status_code=502, detail={"code": err.code, "detail": err.detail})
    return HTTPException(status_code=500, detail={"code": "INTERNAL", "detail": str(err)})


def _vending_failure_http_error(err: VendingFailure) -> HTTPException:
    """FD-4AI: a typed vending failure answers with its class (the Control Center Express route reads
    detail.error_class; never message text)."""
    return HTTPException(status_code=err.http_status,
                         detail={"error_class": err.error_class, "stage": getattr(err, "stage", "vending"),
                                 "detail": err.detail})


# ------------------------------------------------------------------------------
# Request Models
# ------------------------------------------------------------------------------
class CreateFolderRequest(BaseModel):
    display_name: str
    parent_folder_id: Optional[str] = None


class DecommissionProjectRequest(BaseModel):
    action_class: Literal["PROJECT_DECOMMISSION", "SANDBOX_TTL"] = "PROJECT_DECOMMISSION"
    approval_id: Optional[str] = None       # required for PROJECT_DECOMMISSION (minted by the CC for a human ADMIN)
    product_id: Optional[str] = None        # legacy; must equal the path id when given (the target comes from the ledger)
    operator_email: Optional[str] = None    # informational only; the actor is the approval's approver or the caller
    # FD-7L Phase 3 (plan 2.8, Q4): Per-workload installs only; honoured only when the approval itself carries it.
    delete_without_archive: StrictBool = False


class McpApprovalConsumeRequest(BaseModel):
    action: str
    product_id: str
    project_id: str
    binding: Dict[str, Any]


class LifecycleRequest(BaseModel):
    action: Literal["EXTEND", "PROMOTE", "CONFIRM_SANDBOX"]
    ttl_days: Optional[StrictInt] = None
    approval_id: Optional[str] = None       # required for CONFIRM_SANDBOX


class SandboxVendFields(BaseModel):
    """Explicit sandbox designation from the operator's choice (CC / API). Absent -> not a sandbox."""
    is_sandbox: StrictBool = False
    sandbox_auto_decommission: StrictBool = False
    sandbox_designation_source: Optional[str] = None
    sandbox_ttl_days: Optional[StrictInt] = None


class RedeployProjectRequest(BaseModel):
    product_id: Optional[str] = None
    operator_email: Optional[str] = "admin"
    terraform_service_url: Optional[str] = None
    target_folder_id: Optional[str] = None


class VendProjectRequest(SandboxVendFields):
    product_id: str
    trace_id: Optional[str] = None
    folder_id: Optional[str] = None
    billing_account_id: Optional[str] = None
    initial_budget: Optional[float] = None   # FD-4CI-b: None = keep the record's budget, else the platform default


class VendRepoRequest(BaseModel):
    product_id: str
    github_owner: Optional[str] = None
    auto_protect_branch: Optional[bool] = True
    vcs_provider: Optional[str] = None


class VendAllRequest(SandboxVendFields):
    product_id: str
    trace_id: Optional[str] = None
    folder_id: Optional[str] = None
    billing_account_id: Optional[str] = None
    github_owner: Optional[str] = None
    initial_budget: Optional[float] = None   # FD-4CI-b: None = keep the record's budget, else the platform default
    vcs_provider: Optional[str] = None


class AsyncVendingRequest(SandboxVendFields):
    product_id: str
    trace_id: Optional[str] = None
    folder_id: Optional[str] = None
    billing_account_id: Optional[str] = None
    github_owner: Optional[str] = None
    initial_budget: Optional[float] = None   # FD-4CI-b: None = keep the record's budget, else the platform default
    callback_url: str
    vcs_provider: Optional[str] = None


# ------------------------------------------------------------------------------
# Health Check
# ------------------------------------------------------------------------------
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "project-repo-vending-service",
        "environment": os.getenv("ENVIRONMENT", "prod"),
        "release": release_info.current_release(),  # FD-7C P3a: read-only, from this build's release.json
    }


# ------------------------------------------------------------------------------
# Vending Endpoints
# ------------------------------------------------------------------------------
@app.post("/vend-project")
def vend_project(req: VendProjectRequest):
    """Creates a new isolated GCP child project under the Managed Workloads folder and attaches billing."""
    try:
        trace_id = req.trace_id or f"vend-tr-{req.product_id}"
        return vending_engine.vend_gcp_project(
            product_id=req.product_id,
            trace_id=trace_id,
            folder_id=req.folder_id,
            billing_account_id=req.billing_account_id,
            initial_budget=req.initial_budget,
            **_sandbox_kwargs(req),
        )
    except VendingFailure as vf:
        raise _vending_failure_http_error(vf)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _sandbox_kwargs(req: SandboxVendFields) -> Dict[str, Any]:
    return {
        "is_sandbox": req.is_sandbox,
        "sandbox_auto_decommission": req.sandbox_auto_decommission,
        "sandbox_designation_source": req.sandbox_designation_source,
        "sandbox_ttl_days": req.sandbox_ttl_days,
    }


@app.post("/vend-repo")
def vend_repo(req: VendRepoRequest):
    """Creates a new repository on GitHub or Serverless Git with branch protection. GITHUB-REPO-NAME-NO-PREFIX: an
    existing GitHub repository of that name is used only when the workload record's github_repository_identity names
    it (read here, as vend_all does); any other is refused (GITHUB_REPOSITORY_NAME_TAKEN), an unreadable record too
    (VENDING.WORKLOAD_RECORD_UNREADABLE, 503). This route records nothing on the workload: vend_all does."""
    try:
        recorded_identity = None
        if vending_engine.db is not None and GITHUB_REPOSITORY_IDENTITY_FIELD:
            try:
                snap = vending_engine.db.collection("workloads").document(req.product_id.strip().lower()).get()
                data = snap.to_dict() if snap.exists else None
            except Exception as read_err:  # noqa: BLE001 - never decide ownership without the record
                raise HTTPException(status_code=503, detail={
                    "error_class": WORKLOAD_RECORD_UNREADABLE, "stage": "vending",
                    "detail": f"workloads/{req.product_id} could not be read ({type(read_err).__name__})"})
            if isinstance(data, dict):
                recorded_identity = data.get(GITHUB_REPOSITORY_IDENTITY_FIELD)
        return vending_engine.vend_github_repo(
            product_id=req.product_id,
            github_owner=req.github_owner,
            auto_protect_branch=req.auto_protect_branch if req.auto_protect_branch is not None else True,
            vcs_provider=req.vcs_provider,
            recorded_identity=recorded_identity,
        )
    except HTTPException:
        raise
    except (GitHubOwnerNotOrganizationError, GitHubRepositoryCreateError) as e:
        # GITHUB-ORG-ONLY / GITHUB-REPO-CREATE-FAIL-LOUD: the typed class and stage, never an invented repository
        raise HTTPException(status_code=502, detail={"error_class": e.error_class, "stage": e.stage, "detail": str(e)})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/github-token")
def get_github_token(caller_email: str = Depends(verify_github_token_caller)):
    """Generates a temporary 1-hour GitHub App installation token for an allow-listed caller (GH-TOKEN-CALLERS)."""
    try:
        token = vending_engine.generate_github_jit_token()
        logger.info(f"GitHub installation token issued to {caller_email}")
        return {"token": token, "status": "SUCCESS"}
    except Exception as e:
        logger.error(f"Failed to generate GitHub JIT token: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------------------------------------------------------
# FD-7L Phase 1: runner token broker (runner_broker.py). Inert while the install's mode is PLATFORM ("Shared"):
# every route answers 409 RUNNER_IDENTITY_MODE_PLATFORM after its caller check. Nonces, session keys and tokens are
# never logged.
# ------------------------------------------------------------------------------
class RunnerDispatchRequest(BaseModel):
    product_id: str = Field(..., min_length=1, max_length=128)
    trace_id: str = Field(..., min_length=1, max_length=128)
    branch: str = Field(..., min_length=1, max_length=100)
    mode: str = Field(..., min_length=1, max_length=32)
    callback_url: Optional[str] = Field(None, max_length=2048)
    payload_ref: Optional[str] = Field(None, max_length=1024)
    payload_sha256: Optional[str] = Field(None, min_length=64, max_length=64)
    saved_plan_sha256: Optional[str] = Field(None, min_length=64, max_length=64)


class RunnerRedeemRequest(BaseModel):
    nonce: str = Field(..., min_length=32, max_length=256)
    execution: str = Field(..., min_length=1, max_length=512)


class RunnerSessionRequest(BaseModel):
    session_key: str = Field(..., min_length=64, max_length=256)


class RunnerBackfillResultRequest(RunnerSessionRequest):
    results: List[Dict[str, Any]] = Field(default_factory=list, max_length=500)


class RunnerResultRequest(RunnerSessionRequest):
    result_sha256: str = Field(..., min_length=64, max_length=64)


class RunnerDispatchStatusRequest(BaseModel):
    dispatch_id: str = Field(..., min_length=64, max_length=64)


class RunnerProbeRequest(BaseModel):
    product_ids: Optional[List[str]] = Field(None, max_length=200)
    max: StrictInt = Field(25, ge=1, le=200)


def _runner_broker() -> "rb.RunnerBroker":
    return rb.RunnerBroker(_runner_deps())


def _run_broker(call):
    try:
        return call()
    except rb.ri.RunnerIdentityError as e:
        logger.warning(f"Runner broker refused: {e.code} ({e.stage}): {e.detail}")
        raise _runner_http_error(e)


@app.post("/runner/dispatch")
def runner_dispatch(req: RunnerDispatchRequest, caller_email: str = Depends(verify_runner_server_caller)):
    """Signed dispatch record + single-use nonce, then one tf-applier execution bound to it (plan 2.3)."""
    return _run_broker(lambda: _runner_broker().dispatch(caller_email, req.model_dump()))


@app.post("/runner/redeem")
def runner_redeem(req: RunnerRedeemRequest, caller_email: str = Depends(verify_runner_job_caller)):
    """Once, within the redeem window, by the bound running execution: the verified record + a session key."""
    return _run_broker(lambda: _runner_broker().redeem(caller_email, req.nonce, req.execution))


@app.post("/runner/deployer-token")
def runner_deployer_token(req: RunnerSessionRequest, caller_email: str = Depends(verify_runner_job_caller)):
    """That product's deployer access token (1 h) while the session's execution runs."""
    return _run_broker(lambda: _runner_broker().deployer_token(caller_email, req.session_key))


@app.post("/runner/repo-token")
def runner_repo_token(req: RunnerSessionRequest, caller_email: str = Depends(verify_runner_job_caller)):
    """A read-only token for exactly the pinned repository while the session's execution runs."""
    return _run_broker(lambda: _runner_broker().repo_token(caller_email, req.session_key))


@app.post("/runner/backfill-result")
def runner_backfill_result(req: RunnerBackfillResultRequest,
                           caller_email: str = Depends(verify_runner_job_caller)):
    """Backfill execution results; vending verifies each against the child before it signs a record (re-RT R5)."""
    return _run_broker(lambda: _runner_broker().backfill_result(caller_email, req.session_key, req.results))


@app.post("/runner/result")
def runner_result(req: RunnerResultRequest, caller_email: str = Depends(verify_runner_job_caller)):
    """FD-7L 5b (SAT-37): a synchronous run's result fingerprint, signed into its dispatch record (once)."""
    return _run_broker(lambda: _runner_broker().sign_result(caller_email, req.session_key, req.result_sha256))


@app.post("/runner/dispatch-status")
def runner_dispatch_status(req: RunnerDispatchStatusRequest,
                           caller_email: str = Depends(verify_runner_server_caller)):
    """FD-7L 5b RT L2 (SAT-37): has the dispatcher's bound execution ended (read only)."""
    return _run_broker(lambda: _runner_broker().dispatch_status(caller_email, req.dispatch_id))


@app.post("/runner-identity/probe")
def runner_identity_probe(req: Optional[RunnerProbeRequest] = None,
                          caller_email: str = Depends(verify_destructive_caller)):
    """Per READY record: mint inside vending, test the child's (and the host's) permissions; no token leaves."""
    req = req or RunnerProbeRequest()
    return _run_broker(lambda: _runner_broker().probe(caller_email, req.product_ids, req.max))


@app.post("/runner-identity/resign")
def runner_identity_resign(req: Optional[RunnerProbeRequest] = None,
                           caller_email: str = Depends(verify_destructive_caller)):
    """RT F1: re-sign every verifiable runner identity record older than 72 h with vending's current key (idle
    workloads); a record whose key is already retired is reported, never re-signed."""
    req = req or RunnerProbeRequest()

    def _sweep():
        # FD-7L-F4: the operative-mode record first (None when there is none), then the provenance records
        mode_record = _runner_mode_setting().resign_if_stale()
        return dict(_runner_broker().resign_sweep(caller_email, req.product_ids, req.max), mode_record=mode_record)
    return _run_broker(_sweep)


_RUNNER_SECRET_PATHS = ("/runner/", "/runner-identity/")


@app.exception_handler(RequestValidationError)
async def _validation_error_without_echo(request: Request, exc: RequestValidationError):
    """RT F9: a malformed /runner/* body is answered without echoing its input (a nonce or session key). Every other
    route keeps FastAPI's default 422 answer."""
    if request.url.path.startswith(_RUNNER_SECRET_PATHS):
        errors = [{k: v for k, v in e.items() if k in ("type", "loc", "msg")} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": errors})
    return await request_validation_exception_handler(request, exc)


# FD-7L Phase 3: runner identity status + backfill (Control Center Settings card; runner_identity_backfill.py)
class RunnerIdentityBackfillRequest(BaseModel):
    dry_run: StrictBool = True
    product_ids: Optional[List[str]] = Field(None, max_length=200)
    max: StrictInt = Field(25, ge=1, le=200)
    steps: Optional[List[str]] = Field(None, max_length=9)
    operator_email: Optional[str] = None    # informational (audit); the caller is the authenticated CC identity


@app.get("/runner-identity/status")
def runner_identity_status(limit: int = Query(50, ge=1, le=200),
                           caller_email: str = Depends(verify_destructive_caller)):
    """Read-only. Shared install: the mode only (nothing read). Per workload: per workload provenance, deployer, owner
    and broker grants, bucket, state location, migration cursor, last error; totals. At most `limit` records
    (default 50; RT F2-4: about five REST reads per record)."""
    return _run_broker(lambda: _runner_backfill().status(limit=limit))


@app.post("/runner-identity/backfill")
def runner_identity_backfill(req: Optional[RunnerIdentityBackfillRequest] = None,
                             caller_email: str = Depends(verify_destructive_caller)):
    """Idempotent, resumable, audited backfill and state migration (dry run by default). Per-workload failures are
    typed in the results; a configuration error answers 503."""
    req = req or RunnerIdentityBackfillRequest()
    return _run_broker(lambda: _runner_backfill().run(caller_email, dry_run=req.dry_run, product_ids=req.product_ids,
                                                      max_items=req.max, steps=req.steps,
                                                      operator_email=req.operator_email))


def _runner_backfill():
    _runner_deps()   # an unknown STACKVEND_TF_RUNNER_IDENTITY value -> its typed 503
    return vending_engine.runner_identity_backfill()


# FD-7L-F4: the operative runner identity mode record (Control Center Settings card; runner_identity_mode.py)
class RunnerIdentityModeRequest(BaseModel):
    mode: Literal["PLATFORM", "PER_WORKLOAD"]
    expected_version: StrictInt = Field(..., ge=0)
    operator_email: str = Field(..., min_length=3, max_length=320)   # the CC's verified human ADMIN (recorded)


def _runner_mode_setting():
    _runner_deps()   # an unknown STACKVEND_TF_RUNNER_IDENTITY value -> its typed 503
    return vending_engine.runner_identity_mode_setting()


@app.get("/runner-identity/mode")
def runner_identity_mode_view(caller_email: str = Depends(verify_destructive_caller)):
    """Read-only: the declaration, the operative mode, the signed Settings record (or its typed error), whether it can
    be changed here, what of step A is missing, and the last change entries."""
    return _run_broker(lambda: _runner_mode_setting().view())


@app.post("/runner-identity/mode")
def runner_identity_mode_set(req: RunnerIdentityModeRequest, caller_email: str = Depends(verify_destructive_caller)):
    """Sets the operative mode (signed by vending, with a never-trimmed signed change entry). Refused on an install
    that declares PER_WORKLOAD (RUNNER_IDENTITY_MODE_RETIRED), for PER_WORKLOAD before step A
    (RUNNER_IDENTITY_STEP_A_MISSING), and on a stale expected_version (RUNNER_MODE_CHANGED)."""
    return _run_broker(lambda: _runner_mode_setting().set(caller_email, mode=req.mode,
                                                          expected_version=req.expected_version,
                                                          operator_email=req.operator_email))


def run_vending_in_background(req: AsyncVendingRequest):
    trace_id = req.trace_id or f"vend-async-{req.product_id}"
    with AgentLifecycle("Project-Vending", req.product_id, trace_id, mode="ASYNC CALLBACK") as agent:
        with guaranteed_callback_scope(
            callback_url=req.callback_url,
            trace_id=trace_id,
            stage_name="vending",
            product_id=req.product_id,
            firestore_db=getattr(vending_engine, "db", None),
        ) as outcome:
            logger.info(f"Starting async vending for {req.product_id} [Trace: {trace_id}]")
            try:
                res = vending_engine.vend_all(
                    product_id=req.product_id,
                    trace_id=trace_id,
                    folder_id=req.folder_id,
                    billing_account_id=req.billing_account_id,
                    github_owner=req.github_owner,
                    initial_budget=req.initial_budget,
                    vcs_provider=getattr(req, "vcs_provider", None),
                    **_sandbox_kwargs(req),
                )
            except VendingFailure as vf:
                # FD-4AI: a typed FAILED outcome; the workflow's handle_vending_failure lifts error_class unchanged.
                agent.set_summary(f"Vending failed: {vf}", status="FAILED")
                outcome["status"] = "FAILED"
                outcome["error_class"] = vf.error_class
                outcome["error_stage"] = getattr(vf, "stage", "vending")   # GITHUB-REPO-CREATE-FAIL-LOUD
                outcome["error"] = str(vf)
                return
            agent.set_summary(
                f"Project {res.get('project_id')} vended successfully",
                status="SUCCESS",
            )
            outcome["outputs"] = res
            outcome.update(res)
            outcome["status"] = "SUCCESS"
            outcome["error"] = None


@app.post("/vend-all-async", status_code=status.HTTP_202_ACCEPTED)
def vend_all_async(req: AsyncVendingRequest, background_tasks: BackgroundTasks):
    """
    Asynchronously vends a project and reports back to Cloud Workflows via callback.
    Returns HTTP 202 immediately to prevent orchestrator HTTP timeouts.
    """
    background_tasks.add_task(run_vending_in_background, req)
    return {
        "status": "ACCEPTED",
        "product_id": req.product_id,
        "trace_id": req.trace_id,
        "message": "Project vending dispatched to background worker. Workflow will resume via callback.",
    }


@app.post("/vend-all")
def vend_all(req: VendAllRequest):
    """Atomic pipeline: provisions GCP Project, links Billing, creates GitHub repo, and registers in Firestore."""
    trace_id = req.trace_id or f"vend-all-{req.product_id}"
    with AgentLifecycle("Project-Vending", req.product_id, trace_id, mode="SYNC") as agent:
        try:
            res = vending_engine.vend_all(
                product_id=req.product_id,
                trace_id=trace_id,
                initial_budget=req.initial_budget,
                folder_id=getattr(req, "folder_id", None),
                billing_account_id=getattr(req, "billing_account_id", None),
                github_owner=getattr(req, "github_owner", None),
                vcs_provider=getattr(req, "vcs_provider", None),
                **_sandbox_kwargs(req),
            )
            agent.set_summary(
                f"Project {res.get('project_id')} vended successfully",
                status="SUCCESS",
            )
            return res
        except VendingFailure as vf:
            agent.set_summary(f"Vending failed: {vf}", status="FAILED")
            raise _vending_failure_http_error(vf)
        except Exception as e:
            agent.set_summary(f"Vending failed: {str(e)}", status="FAILED")
            raise HTTPException(status_code=500, detail=str(e))


@app.post("/projects/{product_id}/decommission")
def decommission_project(
    product_id: str,
    req: Optional[DecommissionProjectRequest] = None,
    caller_email: str = Depends(verify_decommission_caller),
):
    """Guarded decommission (lane 18 S1): authenticated caller, destructive guard, delete by project NUMBER, archive
    state, keep GitHub & the Firestore spec. Refusal -> 403/404/409/503 with {code, detail}; failed delete -> 502.
    C10: a caller outside DESTRUCTIVE_CALLERS (the sandbox sweeper job) may request SANDBOX_TTL only."""
    req = req or DecommissionProjectRequest()
    if req.action_class != "SANDBOX_TTL" and caller_email not in dg.caller_config_from_env()[0]:
        raise HTTPException(status_code=403, detail={
            "code": "CALLER_NOT_ALLOWED",
            "detail": f"{caller_email} may request only SANDBOX_TTL decommissions (not {req.action_class})"})
    if req.product_id is not None and req.product_id != product_id:
        raise HTTPException(status_code=400, detail={"code": "PRODUCT_ID_MISMATCH",
                                                     "detail": "body product_id differs from the path"})
    try:
        return vending_engine.decommission_workload(
            product_id=product_id,
            operator_email=req.operator_email,
            approval_id=req.approval_id,
            action_class=req.action_class,
            caller_email=caller_email,
            delete_without_archive=req.delete_without_archive,
        )
    except Exception as e:
        raise _guard_http_error(e)


@app.post("/projects/{product_id}/lifecycle")
def sandbox_lifecycle(
    product_id: str,
    req: LifecycleRequest,
    caller_email: str = Depends(verify_destructive_caller),
):
    """Sandbox EXTEND / PROMOTE / CONFIRM_SANDBOX against the vend-time provenance (lane 18 S1, plan 2.4)."""
    try:
        return vending_engine.sandbox_lifecycle(
            product_id,
            req.action,
            ttl_days=req.ttl_days,
            approval_id=req.approval_id,
            caller_email=caller_email,
        )
    except Exception as e:
        raise _guard_http_error(e)


@app.post("/approvals/{approval_id}/consume")
def consume_mcp_approval(
    approval_id: str,
    req: McpApprovalConsumeRequest,
    caller_email: str = Depends(verify_mcp_approval_consumer),
):
    """APPROVAL-CONSUME-VIA-VENDING (owner 11-07): single-use consumption of an MCP action approval (HELM_UNINSTALL,
    AGENT_ENGINE_DEPLOY, DATASTORE_CREATE) in one guard-database transaction (mcp_approvals.py). 200 {status:
    CONSUMED, ...} only when the record names exactly this action, target and binding; otherwise {code, detail} with
    403 / 404 / 409 / 422 / 503 and nothing is consumed."""
    ctx = vending_engine.guard_context()
    try:
        out = mcp_approvals.consume(ctx.store, approval_id, action=req.action, product_id=req.product_id,
                                    project_id=req.project_id, binding=req.binding, caller_email=caller_email,
                                    now=ctx.clock())
    except mcp_approvals.ConsumeRefused as e:
        logger.warning(f"MCP approval {approval_id!r} not consumed: {e.code}: {e.detail}")
        raise HTTPException(status_code=e.http_status,
                            detail={"code": e.code, "stage": "approval-consume", "detail": e.detail})
    logger.info(f"MCP approval {approval_id} ({out['action']}, {out['product_id']}) consumed by {caller_email}")
    return out


# ------------------------------------------------------------------------------
# Lane 18 v3: deletion-safety tag status + backfill (Control Center Settings; managed_tag_backfill.py)
# ------------------------------------------------------------------------------
class ManagedTagBackfillRequest(BaseModel):
    operator_email: Optional[str] = None    # informational (audit); the caller is the authenticated CC identity


def _store_unavailable(err: Exception) -> HTTPException:
    return HTTPException(status_code=503, detail={"code": "LEDGER_UNAVAILABLE", "detail": str(err)})


@app.get("/guard/managed-tag")
def managed_tag_status(caller_email: str = Depends(verify_destructive_caller)):
    """Read-only: is the stackvend-managed tag set up, which vending-born projects are untagged, which ledger
    workloads have no provenance record (never tagged automatically)."""
    try:
        return mtb.tag_status(vending_engine.guard_context(),
                              organization_raw=os.getenv("STACKVEND_ORGANIZATION_ID"))
    except dg.StoreUnavailable as e:
        raise _store_unavailable(e)


@app.post("/guard/managed-tag/backfill")
def managed_tag_backfill(
    req: Optional[ManagedTagBackfillRequest] = None,
    caller_email: str = Depends(verify_destructive_caller),
):
    """Admin action (CC Settings): bind the tag to provenance-proven, vending-born projects. Non-destructive,
    idempotent, audited per project. Tag not set up -> 503 GUARD_UNCONFIGURED."""
    req = req or ManagedTagBackfillRequest()
    try:
        return mtb.backfill_tags(vending_engine.guard_context(), caller_email=caller_email,
                                 operator_email=req.operator_email)
    except dg.StoreUnavailable as e:
        raise _store_unavailable(e)
    except Exception as e:
        raise _guard_http_error(e)


# RT14-31 / owner decision D4 (11-14): the Control Center may read child-project logs (cc_log_reader.py)
class CCLogReaderBackfillRequest(BaseModel):
    dry_run: StrictBool = False
    operator_email: Optional[str] = None    # informational (audit); the caller is the authenticated CC identity


@app.post("/guard/cc-log-reader/backfill")
def cc_log_reader_backfill(
    req: Optional[CCLogReaderBackfillRequest] = None,
    caller_email: str = Depends(verify_destructive_caller),
):
    """Admin action (CC Settings API): grant the Control Center's runtime SA roles/logging.viewer on every
    provenance-proven, open workload's child project. Additive, idempotent, audited per grant; per-workload failures
    are typed in the results. No host project id -> 503 VENDING.CC_LOG_READER_GRANT_FAILED; unreadable guard
    database -> 503 LEDGER_UNAVAILABLE."""
    req = req or CCLogReaderBackfillRequest()
    try:
        return ccl.backfill(vending_engine.guard_context(), vending_engine.iam_client,
                            host_project_id=vending_engine.platform_project_id, caller_email=caller_email,
                            operator_email=req.operator_email, dry_run=req.dry_run)
    except dg.StoreUnavailable as e:
        raise _store_unavailable(e)
    except ccl.CCLogReaderGrantError as e:
        raise HTTPException(status_code=503, detail={"code": ccl.CC_LOG_READER_GRANT_FAILED,
                                                     "stage": ccl.CC_LOG_READER_STAGE, "detail": e.detail})


@app.post("/folders")
def create_folder_endpoint(req: CreateFolderRequest):
    """Creates a new folder in Google Cloud Resource Manager under root or specified parent."""
    try:
        return vending_engine.create_folder(
            display_name=req.display_name,
            parent_folder_id=req.parent_folder_id,
        )
    except VendingFailure as vf:   # VENDING-CLIENT-FAIL-LOUD: e.g. no Resource Manager client
        raise _vending_failure_http_error(vf)
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/projects/{product_id}/redeploy")
def redeploy_project(product_id: str, req: Optional[RedeployProjectRequest] = None):
    """Redeploys a decommissioned workload into a fresh GCP child project with zero configuration drift."""
    try:
        operator_email = req.operator_email if req and req.operator_email else "admin"
        tf_url = req.terraform_service_url if req else None
        target_folder = req.target_folder_id if req else None
        result = vending_engine.redeploy_workload(
            product_id=product_id,
            operator_email=operator_email,
            terraform_service_url=tf_url,
            target_folder_id=target_folder,
        )
    except VendingFailure as vf:   # VENDING-CLIENT-FAIL-LOUD gap 4: the vend step failed (workload recorded FAILED)
        raise _vending_failure_http_error(vf)
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    if result.get("status") != "ACTIVE":
        # FD vending-redeploy: the terraform deploy did not answer HTTP 200; the workload is FAILED (typed class).
        error_class = result.get("error_class")
        raise HTTPException(status_code=REDEPLOY_FAILURE_HTTP_STATUS.get(error_class, 502), detail={
            "error_class": error_class,
            "detail": result.get("error") or result.get("message"),
            "product_id": result.get("product_id"),
            "project_id": result.get("project_id"),
            "trace_id": result.get("trace_id"),
            "http_status": result.get("http_status"),
            **({"wif_secrets_error": result["wif_secrets_error"]} if result.get("wif_secrets_error") else {}),
        })
    return result



if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
