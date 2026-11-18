"""
Project Castor: Product Control Center Entrypoint
Full-stack web application with topology inspection, Mermaid.js visualizer, Castor Assistant, and verified Google OAuth Access Control.
Lean orchestrator mounting modular domain routers and registering security middleware.
"""

import logging
import sys
import types
_this_mod = sys.modules.get(__name__)
if _this_mod:
    sys.modules["main"] = _this_mod
    sys.modules["cc_main"] = _this_mod

try:
    import requests
except ImportError:
    try:
        from unittest.mock import MagicMock
        requests = MagicMock()
    except Exception:
        requests = None

import os

from fastapi import Depends, FastAPI
from google.oauth2 import id_token

# FD-4N: TEST_MODE / MOCK_MODE are test-only switches. On Cloud Run (K_SERVICE set) either one is a misconfiguration;
# refuse to start instead of serving with test behaviour. Authorization itself never reads them.
if os.getenv("K_SERVICE") and (os.getenv("TEST_MODE") or os.getenv("MOCK_MODE")):
    raise RuntimeError("FD-4N: TEST_MODE/MOCK_MODE must not be set on a deployed Control Center (K_SERVICE is set).")

import authz

from auth import (
    AuthMiddleware,
    AuthorizationMiddleware,
    create_session_token,
    extract_user_email,
    get_user_access_record,
    migrate_legacy_user_roles,
    render_forbidden_html,
    render_sign_in_html,
    verify_admin_access,
    verify_session_token,
    verify_workload_access,
)
from config import (
    DEFAULT_ADMIN_EMAIL,
    ENVIRONMENT,
    GOOGLE_OAUTH_CLIENT_ID,
    PORT,
    PROJECT_ID,
    SESSION_SECRET,
)
from db import (
    db,
    get_cloud_logging,
    get_db,
    get_firestore_db,
    get_pubsub_publisher,
    get_storage,
)
from diagram import ArchitectureDiagramEngine
from assistant import CastorAssistantEngine
from routes import (
    agent_evals,
    approvals,
    assistant,
    finops,
    install_status,
    network_posture,
    platform_release,
    platform_upgrade,
    prompts,
    runner_identity_card,
    settings,
    telemetry,
    users,
    web,
    workloads,
)
from schemas import UserRole

logger = logging.getLogger("control-center-service")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="StackVend Product Control Center Portal",
    description="Central flight deck for StackVend: visual topology, automated architecture diagrams, AI chat assistant, and verified Google OAuth access control.",
    version="2.0.0",
    # FD-4N: deny by default. Every route must declare exactly one policy on its decorator
    # (`dependencies=[authz.require(...)]`); a route without one is answered 403.
    dependencies=[Depends(authz.enforce_declared_policy)],
)

# 1. Global Authentication & Authorization Middleware
app.add_middleware(AuthorizationMiddleware)
# 1b. FD-4AR: CSP + security headers. Added LAST so it is the OUTERMOST middleware: the 401/403 pages rendered inside
# AuthorizationMiddleware need the per-request nonce and the headers too.
from security_headers import SecurityHeadersMiddleware  # noqa: E402

app.add_middleware(SecurityHeadersMiddleware)

# 2. Register Modular Route Controllers
app.include_router(web.router)
app.include_router(workloads.router)
app.include_router(approvals.router)
app.include_router(settings.router)
app.include_router(users.router)
app.include_router(finops.router)
app.include_router(telemetry.router)
app.include_router(assistant.router)
app.include_router(agent_evals.router)
app.include_router(prompts.router)
app.include_router(install_status.router)  # lane 18 v3: Settings install warnings (tag admin, CC billing viewer)
app.include_router(platform_release.router)  # FD-7C P3a + FD-4DA (3): Settings > Upgrades (version, release source, sync)
app.include_router(platform_upgrade.router)  # SELFUP P3b: Settings > Upgrades > Update StackVend (request + lease + one message)
app.include_router(runner_identity_card.router)  # FD-7L Phase 3: Settings "Terraform runner identity" card
app.include_router(network_posture.router)  # CC-NETWORK-POSTURE: Settings "Platform network" card (read-only)

# 2a. FD-4AR: vendored, SRI-pinned browser scripts (static/vendor/VENDOR_MANIFEST.json). The only static mount and
# public by design (the sign-in page loads Tailwind + Alpine before login); see authz.PUBLIC_STATIC_PREFIX.
# Skipped only when `fastapi` is not a real package (some legacy root-suite tests replace it with a MagicMock);
# with the real framework the import is unconditional and a failure stops the boot.
if hasattr(sys.modules.get("fastapi"), "__path__"):
    from fastapi.staticfiles import StaticFiles

    app.mount(
        authz.PUBLIC_STATIC_MOUNT,
        StaticFiles(directory=os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "vendor")),
        name="vendor",
    )

# 2b. FD-4N startup self-check: refuse to boot if any effective route lacks an authorization policy
# (Cloud Run then keeps serving the previous revision).
authz.assert_all_routes_have_policy(app)

# 3. Startup Migrations
if db:
    try:
        migrate_legacy_user_roles(db)
    except Exception as e:
        logger.warning(f"Startup user role migration notice: {e}")

# 3b. Resolve and log the identity mode (IAP vs public, bearer audiences) once per instance.
import identity  # noqa: E402


@app.on_event("startup")
def _warm_identity_mode():
    identity.get_runtime_identity()
    # Lane 19 L19-0c: publish which OAuth client this revision verifies logins against (platform_config/cc_identity).
    web.publish_cc_identity()

# 4. Backward Compatibility Re-Exports (Guarantees zero breakage for test_portal.py and external consumers)
project_id = PROJECT_ID

try:
    from google.cloud import logging as cloud_logging
except Exception:
    cloud_logging = None

from schemas import *

# Web
index_page = web.index_page
auth_google_login = web.auth_google_login
config_client_id = web.config_client_id
auth_logout = web.auth_logout
health_check = web.health_check

# Workloads
list_workloads = workloads.list_workloads
create_workload = workloads.create_workload
bootstrap_castor_workload = workloads.bootstrap_castor_workload
get_workload_details = workloads.get_workload_details
submit_feature_request = workloads.submit_feature_request
list_feature_requests = workloads.list_feature_requests
get_feature_request_detail = workloads.get_feature_request_detail
get_workload_build_plans = workloads.get_workload_build_plans
get_build_plan_by_trace = workloads.get_build_plan_by_trace
get_workload_implementation_plans = workloads.get_workload_implementation_plans
get_workload_plan_content = workloads.get_workload_plan_content
get_workload_plan_raw = workloads.get_workload_plan_raw
retrigger_feature_request_build = workloads.retrigger_feature_request_build
update_workload_budget = workloads.update_workload_budget
get_workload_policies = workloads.get_workload_policies
update_workload_policies = workloads.update_workload_policies
decommission_workload_endpoint = workloads.decommission_workload_endpoint
cancel_workload_active_executions = workloads.cancel_workload_active_executions
redeploy_workload_endpoint = workloads.redeploy_workload_endpoint
deploy_workload_to_folder_endpoint = workloads.deploy_workload_to_folder_endpoint
parse_tfstate_json = workloads.parse_tfstate_json
get_platform_default_deployed_assets = workloads.get_platform_default_deployed_assets
fetch_workload_state_from_gcs = workloads.fetch_workload_state_from_gcs
create_or_verify_branch = workloads.create_or_verify_branch

# Approvals
list_pending_approvals = approvals.list_pending_approvals
decide_approval_request = approvals.decide_approval_request
approval_callback_webhook = getattr(approvals, "approval_callback_webhook", None)

# Settings
get_emergency_stop_status = settings.get_emergency_stop_status
toggle_emergency_stop_api = settings.toggle_emergency_stop_api
get_settings_api = settings.get_settings_api
update_settings_api = settings.update_settings_api
reset_settings_defaults_api = settings.reset_settings_defaults_api
get_billing_status_api = settings.get_billing_status_api
get_vcs_status_api = settings.get_vcs_status_api
list_managed_folders_api = settings.list_managed_folders_api
get_vending_service_url = settings.get_vending_service_url
get_google_id_token = settings.get_google_id_token
make_vending_request = settings.make_vending_request
create_managed_folder_api = settings.create_managed_folder_api
set_default_managed_folder_api = settings.set_default_managed_folder_api
delete_managed_folder_api = settings.delete_managed_folder_api
get_ipam_allocations_endpoint = settings.get_ipam_allocations_endpoint
_CACHED_VENDING_SERVICE_URL = getattr(settings, "_CACHED_VENDING_SERVICE_URL", None)
get_github_token = getattr(settings, "get_github_token", lambda *args, **kwargs: "")
get_token_manager = getattr(settings, "get_token_manager", lambda *args, **kwargs: None)

# FinOps
calculate_run_rate_projection = finops.calculate_run_rate_projection
sync_all_spend = finops.sync_all_spend
sync_workload_spend = finops.sync_workload_spend

# Telemetry
diagram_engine = telemetry.diagram_engine
fetch_workload_logs_from_cloud_logging = telemetry.fetch_workload_logs_from_cloud_logging
fetch_trace_logs_from_cloud_logging = telemetry.fetch_trace_logs_from_cloud_logging
get_castor_agent_roster = telemetry.get_castor_agent_roster
get_castor_tool_servers_roster = telemetry.get_castor_tool_servers_roster
build_pipeline_overview = telemetry.build_pipeline_overview
get_active_pipeline_executions = telemetry.get_active_pipeline_executions
get_pipeline_execution = telemetry.get_pipeline_execution
get_pipeline_execution_logs = telemetry.get_pipeline_execution_logs
get_pipeline_flight_deck_telemetry = telemetry.get_pipeline_flight_deck_telemetry
abort_pipeline_execution = telemetry.abort_pipeline_execution
get_workload_logs = telemetry.get_workload_logs
get_pipeline_overview = telemetry.get_pipeline_overview
get_pipeline_agents = telemetry.get_pipeline_agents
get_architecture_diagram = telemetry.get_architecture_diagram

# Assistant
assistant_engine = assistant.assistant_engine
assistant_chat = assistant.assistant_chat

# Users
list_approved_users = users.list_approved_users
add_approved_user = users.add_approved_user
update_user_workloads = users.update_user_workloads
remove_approved_user = users.remove_approved_user

__all__ = [
    "app",
    "db",
    "id_token",
    "requests",
    "project_id",
    "DEFAULT_ADMIN_EMAIL",
    "GOOGLE_OAUTH_CLIENT_ID",
    "SESSION_SECRET",
    "UserRole",
    "verify_admin_access",
    "verify_workload_access",
    "get_firestore_db",
    "get_pubsub_publisher",
    "get_storage",
    "get_cloud_logging",
    "get_db",
    "create_session_token",
    "verify_session_token",
    "extract_user_email",
    "get_user_access_record",
    "render_sign_in_html",
    "render_forbidden_html",
    "calculate_run_rate_projection",
    "diagram_engine",
    "assistant_engine",
    "ArchitectureDiagramEngine",
    "CastorAssistantEngine",
    "AuthMiddleware",
    "AuthorizationMiddleware",
]

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PORT)
