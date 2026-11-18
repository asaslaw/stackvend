"""
Project Castor: Product Control Center Pydantic Schemas
Defines request/response contracts for workload management, architecture diagrams, conversational assistant, and verified Google OAuth access control.
"""

from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import (BaseModel, ConfigDict, EmailStr, Field, StrictBool, StrictStr, ValidationError, field_validator,
                      model_validator)

# Lane 19 L19-11: the access intake is validated by the one access model (byte-identical replica of root
# shared/access_policy.py, policed by tests/test_shared_packaging.py). No fallback: without it the CC must not start.
from shared.access_policy import (
    AccessMode,
    AccessPolicy,
    AccessPolicyIncompleteError,
    GoogleIdpMode,
    SignInPolicy,
    widening_changes,
)
# FD-4CI-b-R1-API: an explicit branch on the API is checked with the same typed check as Settings > Default GitHub
# Branch (byte-identical replica of root shared/settings.py). No fallback, as for access_policy.
from shared.settings import is_branch_name

BRANCH_NAME_RULE = ("a Git branch name is 1-100 letters, digits, '.', '_', '-' or '/', with no leading '-' or '/', no "
                    "trailing '/' or '.', no '..', no empty path component, no component starting with '.' or ending "
                    "in '.lock', and not exactly 'HEAD'")


def branch_name_refusal(field: str, value: Any, absent_means: str) -> str:
    """FD-4CI-b-R1-API: the 422 message for an explicit branch that is not a plain branch name (is_branch_name)."""
    return f"{field} {value!r} is not a valid Git branch name ({BRANCH_NAME_RULE}). Omit it to use {absent_means}."

try:
    from shared.iac_upgrade_schema import (
        IaCAssetType,
        IaCModuleStatus,
        IaCDriftStatusResponse,
        IaCUpgradeRecord,
        IaCUpgradeHistoryResponse,
        TriggerIaCUpgradeRequest,
    )
except ImportError:
    from iac_upgrade_schema import (  # type: ignore
        IaCAssetType,
        IaCModuleStatus,
        IaCDriftStatusResponse,
        IaCUpgradeRecord,
        IaCUpgradeHistoryResponse,
        TriggerIaCUpgradeRequest,
    )


class IaCEngineType(str, Enum):
    TERRAFORM = "TERRAFORM"
    OPENTOFU = "OPENTOFU"


class ComplianceProfile(str, Enum):
    """compliance-profile-explicit: the exact compliance profiles (same vocabulary as the compliance plan gate,
    mcp-servers/compliance/plan_gate.py::KNOWN_PROFILES; tests/test_compliance_profile_explicit.py checks parity).
    The profile is chosen here, explicitly; it is never inferred from the spec text."""
    STANDARD = "STANDARD"
    HIPAA = "HIPAA"
    FEDRAMP_MODERATE = "FEDRAMP_MODERATE"
    FEDRAMP_HIGH = "FEDRAMP_HIGH"
    CJIS = "CJIS"
    EU_REGIONS_AND_SUPPORT = "EU_REGIONS_AND_SUPPORT"
    PCI_DSS = "PCI_DSS"


# Owner decisions 10-18 (rows CP-8..CP-11): profile strictness, the same table as
# apps/orchestrator-gateway/compliance_agent/profiles.py (parity test). rank: higher = stricter; family: region family.
PROFILE_STRICTNESS = {
    "STANDARD":               (0, None),
    "PCI_DSS":                (1, "US"),
    "HIPAA":                  (2, "US"),
    "FEDRAMP_MODERATE":       (3, "US"),
    "CJIS":                   (4, "US"),
    "FEDRAMP_HIGH":           (5, "US"),
    "EU_REGIONS_AND_SUPPORT": (3, "EU"),
}


# FD-7M-a (OQ-25, owner 10-31): the regions each regulated profile allows. An exact copy of the compliance server's
# table (developer_agent/compliance_profile.py PROFILE_REQUIREMENTS[*]["allowed_regions"]; parity test in
# tests/test_fd7m_a_regions_cc.py). STANDARD is not listed: it allows every approved region. Used only to refuse a
# create whose region the profile does not allow (REGION_PROFILE_CONFLICT), before the apply-time gate would.
PROFILE_ALLOWED_REGIONS = {
    "HIPAA": ("us-central1", "us-east1", "us-east4", "us-west1"),
    "FEDRAMP_MODERATE": ("us-central1", "us-east1", "us-east4"),
    "FEDRAMP_HIGH": ("us-central1", "us-east1", "us-east4"),
    "CJIS": ("us-central1", "us-east1", "us-east4"),
    "EU_REGIONS_AND_SUPPORT": ("europe-west1", "europe-west3", "europe-west4", "europe-north1"),
    "PCI_DSS": ("us-central1", "us-east1", "us-east4"),
}


def profile_is_downgrade(stored: Optional[str], requested: Optional[str]) -> bool:
    """CP-11: a stored REGULATED profile replaced by one that is not at least as strict needs an admin approval."""
    if not stored or not requested or stored == "STANDARD" or stored == requested:
        return False
    if stored not in PROFILE_STRICTNESS or requested not in PROFILE_STRICTNESS:
        return True  # unknown stored value: never silently replaced
    rs, fs = PROFILE_STRICTNESS[stored]
    rr, fr = PROFILE_STRICTNESS[requested]
    return fr != fs or rr < rs


class BudgetBreachPolicy(str, Enum):
    AUTONOMOUS_SCALE_TO_ZERO = "AUTONOMOUS_SCALE_TO_ZERO"
    ALERT_ONLY = "ALERT_ONLY"
    HITL_CONFIRMATION_REQUIRED = "HITL_CONFIRMATION_REQUIRED"
    NUCLEAR_UNLINK_BILLING = "NUCLEAR_UNLINK_BILLING"


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    WORKLOAD_MANAGER = "WORKLOAD_MANAGER"
    VIEWER = "VIEWER"
    # Legacy alias support for zero-downtime transition
    APPROVER = "APPROVER"


class UserAccessRecord(BaseModel):
    email: str = Field(description="Authorized user email address")
    role: UserRole = Field(default=UserRole.VIEWER)
    assigned_workloads: List[str] = Field(
        default_factory=list,
        description="List of product_ids this user is permitted to view or manage (empty for ADMIN)",
    )
    added_at: str = Field(description="ISO timestamp when email was approved")
    added_by: Optional[str] = Field(default="system", description="Admin user who added this email")
    is_active: bool = Field(default=True)

    def __init__(self, **data):
        raw_role = data.get("role")
        if raw_role == "APPROVER" or getattr(raw_role, "value", None) == "APPROVER":
            data["role"] = UserRole.WORKLOAD_MANAGER
        elif isinstance(raw_role, str):
            clean_role = raw_role.strip().upper()
            if clean_role == "APPROVER":
                data["role"] = UserRole.WORKLOAD_MANAGER
            elif clean_role in UserRole.__members__:
                data["role"] = UserRole[clean_role]
        if "assigned_workloads" not in data or data["assigned_workloads"] is None:
            data["assigned_workloads"] = []
        super().__init__(**data)


class AddUserRequest(BaseModel):
    email: str
    role: Optional[UserRole] = UserRole.VIEWER
    assigned_workloads: List[str] = Field(
        default_factory=list,
        description="Workload slugs assigned to this user. Ignored if role is ADMIN.",
    )


class UpdateUserWorkloadsRequest(BaseModel):
    assigned_workloads: List[str] = Field(
        default_factory=list,
        description="Updated list of assigned product_ids",
    )
    role: Optional[UserRole] = None


class GoogleLoginRequest(BaseModel):
    credential: str = Field(description="Cryptographically signed Google ID Token (JWT) from Google Identity Services")


class ManagedFolder(BaseModel):
    folder_id: str = Field(description="Full Resource Manager folder resource name (e.g. folders/123456789012)")
    folder_number: str = Field(description="Raw numerical folder ID")
    display_name: str = Field(description="Human-readable folder label")
    description: Optional[str] = Field(default="")
    parent_folder_id: Optional[str] = Field(default=None, description="Parent folder ID or None if root")
    is_default: bool = Field(default=False, description="Whether this is the platform fallback folder")
    status: str = Field(default="ACTIVE", description="ACTIVE or DISABLED")
    created_at: Optional[str] = None
    created_by: Optional[str] = Field(default="system")
    updated_at: Optional[str] = None


class CreateFolderRequest(BaseModel):
    display_name: str
    description: Optional[str] = Field(default="")
    parent_folder_id: Optional[str] = Field(default=None)
    is_default: bool = Field(default=False)


class DeployToFolderRequest(BaseModel):
    destination_folder_id: str = Field(description="Target GCP folder ID where new project will be created")
    new_product_id: str = Field(description="New workload product_id for this environment")
    target_branch: str = Field(description="Name of new Git branch to create and deploy (e.g. prod, staging)")
    copy_feature_requests: bool = Field(default=False)

    @field_validator("target_branch")
    @classmethod
    def _target_branch_is_a_branch_name(cls, value: str) -> str:
        # FD-4CI-b-R1-API: the promotion creates this branch in the repository. The route strips it and uses "prod"
        # when nothing is left (unchanged); anything else must be a plain branch name after that strip, else 422.
        # The value is returned as sent (checked, never rewritten here).
        if value.strip() and not is_branch_name(value.strip()):
            raise ValueError(branch_name_refusal("target_branch", value, "'prod'"))
        return value


class RedeployRequestWithFolder(BaseModel):
    target_folder_id: Optional[str] = Field(default=None, description="Optional target folder ID override during rehydration")


class WorkloadSummary(BaseModel):
    product_id: str
    project_id: str
    github_repo: Optional[str] = Field(default=None, description="GitHub repository in owner/repo format")
    vcs_provider: Optional[str] = Field(default="GITHUB", description="VCS provider: GITHUB or SERVERLESS_GIT")
    default_branch: Optional[str] = Field(default="main", description="Primary repository branch")
    folder_id: Optional[str] = Field(default=None, description="GCP folder ID where workload is provisioned")
    folder_name: Optional[str] = Field(default=None, description="Human-readable folder display name")
    status: str
    budget_ceiling_monthly_usd: float
    current_spend_usd: float = Field(default=0.0)
    projected_monthly_spend_usd: Optional[float] = Field(default=None, description="Extrapolated end-of-month spend run rate based on day-of-month progress")
    spend_last_updated_at: Optional[str] = Field(default=None, description="Timestamp of the most recent FinOps spend calculation")
    is_overrun_projected: bool = Field(default=False, description="True if projected monthly spend exceeds the budget ceiling")
    spend_source: Optional[str] = Field(default=None, description="Spend data origin: GCP_BILLING_EXPORT or ESTIMATED_ACTIVE_ACCRUAL")
    cached_hourly_burn_usd: Optional[float] = Field(default=None, description="Cached hourly burn rate in USD calculated from deployed infrastructure")
    service_url: Optional[str] = None
    service_url_unknown_reason: Optional[str] = Field(default=None, description="Typed reason the last deploy could not read its service URL (the URL is then unknown, never guessed)")
    created_at: Optional[str] = None
    is_castor: bool = Field(default=False, description="True if this workload is the StackVend platform itself, False for other workloads")
    iac_engine: Optional[str] = Field(default="TERRAFORM", description="IaC engine used for this workload: TERRAFORM or OPENTOFU")
    region: Optional[str] = Field(default=None, description="FD-7M-a / SAT-44: the region recorded at creation (shown on "
                                                            "the Workloads Catalog card). None: a workload created before "
                                                            "approved regions; it follows Settings > Default Workload Region.")
    code_freeze: bool = Field(default=False, description="Master freeze toggle preventing all autonomous agent code changes or PRs")
    sre_auto_healing_enabled: bool = Field(default=True, description="Enables autonomous SRE hotfix workflow execution on runtime crashes")
    require_human_code_review: bool = Field(default=True, description="Requires manual review before merging Pull Requests into main (Auto-Merge disabled)")
    auto_merge: bool = Field(default=False, description="True if autonomous auto-merge into main is enabled without manual review")
    require_plan_approval: bool = Field(default=False, description="Requires manual review and approval of the architectural plan before Developer Agent code generation")
    budget_breach_policy: Optional[str] = Field(default="AUTONOMOUS_SCALE_TO_ZERO", description="Breach policy: AUTONOMOUS_SCALE_TO_ZERO, ALERT_ONLY, HITL_CONFIRMATION_REQUIRED, NUCLEAR_UNLINK_BILLING")
    buffer_ceiling_usd: Optional[float] = Field(default=None, description="Temporary overrun buffer ceiling in USD (+15%)")
    decommissioned_at: Optional[str] = None
    decommissioned_by: Optional[str] = None
    archived_at: Optional[str] = None
    archived_by: Optional[str] = None
    last_active_project_id: Optional[str] = None
    last_iac_upgrade_at: Optional[str] = Field(default=None, description="Timestamp of the most recent IaC module/bundle upgrade")
    last_iac_upgrade_by: Optional[str] = Field(default=None, description="User or service who triggered the last IaC upgrade")
    last_iac_upgrade_status: Optional[str] = Field(default=None, description="Status of the last IaC upgrade (SUCCESS, FAILED, ROLLED_BACK)")
    iac_drift_detected: Optional[bool] = Field(default=None, description="True if any vendored modules have newer upstream releases or content drift")
    iac_drift_count: Optional[int] = Field(default=0, description="Count of outdated or drifted vendored modules")
    # --- Autonomous Sandbox Lifespan Fields ---
    is_sandbox: bool = Field(default=False, description="True if workload is an ephemeral sandbox")
    sandbox_ttl_days: Optional[int] = Field(default=30, description="Configured sandbox lifespan in days")
    sandbox_expires_at: Optional[str] = Field(default=None, description="ISO timestamp when sandbox expires")
    sandbox_days_remaining: Optional[float] = Field(default=None, description="Calculated days remaining before auto-decommissioning")
    sandbox_auto_decommission: bool = Field(default=True, description="True if auto-decommission is active")
    sandbox_designation_source: Optional[str] = Field(default=None, description="How the workload became a sandbox: API_FIELD / OPERATOR_CHECKBOX / OPERATOR_CONFIRMED (explicit) or KEYWORD_DETECTED / none (not auto-deleted until confirmed)")
    sandbox_awaiting_confirmation: bool = Field(default=False, description="True for a sandbox whose designation is not explicit: it is deleted only after an ADMIN confirms it (POST /api/workloads/{id}/sandbox/confirm)")
    ttl_authority: Optional[str] = Field(default=None, description="VENDING_PROVENANCE (vending enforces the expiry) or LEDGER_DISPLAY_ONLY (the countdown is informational; nothing auto-deletes the project)")
    sandbox_decommission_status: Optional[str] = Field(default=None, description="SCHEDULED, EXTENDED, EXPIRATION_IMMINENT, DEFERRED_ACTIVE_PIPELINE, DEFERRED_PENDING_REVIEW, GUARD_REFUSED (sweep guard refused the delete), DECOMMISSION_FAILED (CRM delete failed), EXPIRED, DECOMMISSIONED, or PROMOTED")
    cumulative_lifespan_days: int = Field(default=30, description="Total cumulative days workload has run as a sandbox")
    extension_count: int = Field(default=0, description="Number of times lifecycle extension was granted")
    max_extensions_allowed: int = Field(default=3, description="Maximum number of lifecycle extensions allowed")
    max_cumulative_days_allowed: int = Field(default=90, description="Maximum cumulative lifespan days allowed")
    creator_email: Optional[str] = Field(default=None, description="Email of the creator / owner for notifications")
    # COMPLIANCE-BASELINE-LABEL (owner 10-27): display only (apps/control-center/compliance_label.py).
    compliance_label: Optional[str] = Field(default=None, description="Standard / 'Compliance: <regime> (Assured Workloads)' (profile from the folder's Assured Workloads regime) / 'Controls: <regime> baseline (not a compliance environment)'")
    compliance_label_kind: Optional[str] = Field(default=None, description="STANDARD, COMPLIANCE_ENVIRONMENT or CONTROLS_BASELINE")
    # BUILD-ADMISSION-QUEUE (G4): set on a create / promote answer (HTTP 202) when the build waits for a build slot.
    build_queue: Optional[Dict[str, Any]] = Field(default=None, description="When the build waits in the build queue: "
                                                  "{state: QUEUED, trace_id, position, ahead, limit, running}")


class DecommissionRequest(BaseModel):
    confirm_product_id: str = Field(description="Exact workload ID typed by operator for high-friction safety verification")
    reason: Optional[str] = Field(default=None, description="Operational justification for decommissioning")
    approval_id: Optional[str] = Field(default=None, description="Optional associated HITL approval ID")
    delete_without_archive: bool = Field(default=False, description=(
        "FD-7L (Per-workload installs): delete the project even if the state archive copy fails. Recorded in the "
        "approval; vending honours it only from the approval."))


class DecommissionResponse(BaseModel):
    status: str = "DECOMMISSIONED"
    product_id: str
    message: str
    deleted_project_id: Optional[str] = None
    decommissioned_at: str
    decommissioned_by: str
    last_active_project_id: Optional[str] = None
    # SAT-43: pipeline runs left un-aborted because their workflow execution could not be cancelled (may still run).
    workflow_cancel_failures: List[Dict[str, Any]] = Field(default_factory=list, description="{trace_id, execution, reason, detail} per run not aborted")


class ArchiveWorkloadResponse(BaseModel):
    status: str = "ARCHIVED"
    product_id: str
    message: str
    archived_at: str
    archived_by: str


class UnarchiveWorkloadResponse(BaseModel):
    status: str = "DECOMMISSIONED"
    product_id: str
    message: str
    unarchived_at: str
    unarchived_by: str


class ExtractedDocumentResponse(BaseModel):
    filename: str
    file_type: str
    character_count: int
    word_count: int
    pages_count: Optional[int] = None
    suggested_slug: Optional[str] = None
    suggested_title: Optional[str] = None
    text: str


class RedeployResponse(BaseModel):
    status: str = "ACTIVE"
    product_id: str
    message: str
    new_project_id: Optional[str] = None
    service_url: Optional[str] = None
    redeployed_at: str
    redeployed_by: str
    # RT14-18: typed VENDING.GHA_SECRETS_NOT_WRITTEN body when the GitHub Actions deploy secrets were not written
    # (the redeploy itself completed; GitHub Actions deploys of the new project fail until they are written).
    wif_secrets_error: Optional[Dict[str, Any]] = None


class ExtendSandboxRequest(BaseModel):
    extend_days: int = Field(default=30, ge=1, le=30, description="Number of additional days to extend sandbox lifespan (1 to 30 days, default: 30)")
    reason: Optional[str] = Field(default="Testing extension approved by operator", description="Operational justification")


class ExtendSandboxResponse(BaseModel):
    product_id: str
    previous_expires_at: str
    new_expires_at: str
    sandbox_days_remaining: float
    cumulative_lifespan_days: int
    extension_count: int
    message: str


class PromoteSandboxResponse(BaseModel):
    product_id: str
    is_sandbox: bool = False
    message: str


class ConfirmSandboxRequest(BaseModel):
    """Lane 18 S2: a human ADMIN confirms auto-decommission for a sandbox whose designation was not explicit."""
    ttl_days: int = Field(default=30, ge=1, le=30, description="Days until auto-decommission (1 to 30, default 30)")
    reason: Optional[str] = Field(default=None, description="Operational justification")


class ConfirmSandboxResponse(BaseModel):
    product_id: str
    sandbox_expires_at: Optional[str] = None
    message: str


class SandboxSweepResult(BaseModel):
    scanned_count: int
    expired_count: int
    decommissioned_workloads: List[str] = Field(default_factory=list)
    deferred_workloads: List[str] = Field(default_factory=list)
    notifications_sent: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    # C10 (RT finding 4): expired sandboxes vending never TTL-deletes (not sent), and typed vending refusals (403 / 409)
    not_eligible_workloads: List[str] = Field(default_factory=list)
    refused_workloads: List[str] = Field(default_factory=list)


class BuildPlanStepSummary(BaseModel):
    step_id: str
    step_index: int
    category: str
    title: str
    target_files: List[str] = Field(default_factory=list)
    description: str
    acceptance_criteria: List[str] = Field(default_factory=list)
    depends_on: List[str] = Field(default_factory=list)
    status: str = Field(default="PENDING")
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    output_summary: Optional[str] = None


class BuildPlanResponse(BaseModel):
    plan_id: str
    product_id: str
    trace_id: str
    build_type: str = Field(default="INITIAL_BUILD")
    feature_request_id: Optional[str] = None
    title: str
    summary: str
    created_at: str
    total_steps: int
    status: str
    required_cloud_apis: List[str] = Field(default_factory=list)
    steps: List[BuildPlanStepSummary] = Field(default_factory=list)


class WorkloadBuildPlansResponse(BaseModel):
    product_id: str
    total_count: int
    build_plans: List[BuildPlanResponse] = Field(default_factory=list)


class WorkloadPlanItem(BaseModel):
    filename: str
    file_path: str
    title: str
    status: str = "PLANNED"
    tier: Optional[int] = 1
    created_at: Optional[str] = None
    trace_id: Optional[str] = None
    url: Optional[str] = None
    markdown: Optional[str] = None


class WorkloadPlansResponse(BaseModel):
    product_id: str
    total_plans: int
    plans: List[WorkloadPlanItem] = Field(default_factory=list)


class UpdateBudgetRequest(BaseModel):
    budget_ceiling_monthly_usd: float


class ModuleInstanceConfig(BaseModel):
    module_id: str = Field(description="Selected Golden Module ID or Custom Module ID, e.g. 'compute-cloudrun', 'networking-vpc'")
    instance_name: str = Field(description="Unique instance identifier, e.g. 'gateway', 'orders-db'")
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Custom parameters / variables for this module instance")


class AccessIntake(BaseModel):
    """Lane 19 L19-11: who may use the generated app, as the submitter states it (never inferred, never guessed).

    The full ``shared.access_policy.AccessPolicy`` (the ``workloads/{pid}.access`` record the developer reads) is
    composed from these three answers by ``to_policy``; validation runs here, so an invalid answer is a 422 at the
    door: principals must be exact ``user:`` / ``group:`` / ``serviceAccount:`` / ``domain:`` members (nothing is
    prefixed, trimmed or widened); ``PUBLIC_APP`` takes no principals and needs the A8 answer
    (``tenant_isolation_required``: True / False, no default); a private mode needs at least one principal
    (``ACCESS_POLICY_INCOMPLETE``)."""

    model_config = ConfigDict(extra="forbid")

    mode: AccessMode = Field(description="PRIVATE_IAP (Google sign-in via IAP), PRIVATE_IAM (invoker IAM only) or PUBLIC_APP")
    invoker_principals: List[StrictStr] = Field(
        default_factory=list,
        description="Private modes: exact IAM members, e.g. user:ana@example.com, group:team@example.com, domain:example.com",
    )
    tenant_isolation_required: Optional[StrictBool] = Field(
        default=None,
        description="PUBLIC_APP only (A8, row 45): does this app handle money, personal data, or other customers' data? "
                    "Required for PUBLIC_APP, no default; must be unset for private modes.",
    )

    def to_policy(self, source: str) -> AccessPolicy:
        """The complete record. Private modes: Google sign-in DISABLED (rows 42/46: IAP / IAM only). PUBLIC_APP: the
        shared platform Google client, or the app's own client (BYO) when tenant isolation is required (A8, row 45)."""
        if self.mode is AccessMode.PUBLIC_APP:
            google = GoogleIdpMode.BYO if self.tenant_isolation_required is True else GoogleIdpMode.SHARED_PLATFORM_CLIENT
        else:
            google = GoogleIdpMode.DISABLED
        return AccessPolicy(mode=self.mode, invoker_principals=list(self.invoker_principals),
                            sign_in=SignInPolicy(google=google),
                            tenant_isolation_required=self.tenant_isolation_required, source=source)

    @model_validator(mode="after")
    def _composes_to_a_complete_policy(self) -> "AccessIntake":
        if self.mode is not AccessMode.PUBLIC_APP and self.tenant_isolation_required is not None:
            # RT F7: the A8 answer only means something for PUBLIC_APP; a private record never stores one.
            raise ValueError(f"{self.mode.value} takes no tenant_isolation_required answer (A8 is for PUBLIC_APP only)")
        try:
            self.to_policy("intake").require_complete()
        except AccessPolicyIncompleteError as e:
            raise ValueError(f"{e.error_class}: {e}") from None
        except ValidationError as e:  # report the AccessPolicy messages, not a nested pydantic dump
            raise ValueError("; ".join(str(err.get("msg", "")) for err in e.errors()[:3])) from None
        return self


def access_record(policy: AccessPolicy) -> Dict[str, Any]:
    """The stored ``workloads/{pid}.access`` map: the policy's JSON form with principals as exact ``kind:value``
    strings (the shape operators read and the developer validates again with the same model)."""
    record = policy.model_dump(mode="json")
    record["invoker_principals"] = policy.invoker_members()
    return record


def access_widening(previous_record: Any, new_policy: AccessPolicy) -> List[str]:
    """L19-F4: how ``new_policy`` widens the stored ``previous_record`` (``WideningChange`` values; [] = none).

    The stored record is validated with the same model; a missing, non-map or invalid record is "nothing valid
    recorded" (``NO_PREVIOUS_RECORD``), so replacing it is always a widening (fail closed: confirm + plan approval)."""
    return [c.value for c in widening_changes(stored_access_policy(previous_record), new_policy)]


def stored_access_policy(previous_record: Any) -> Optional[AccessPolicy]:
    """The stored ``workloads/{pid}.access`` map validated by the access model; None when missing, not a map or invalid."""
    if isinstance(previous_record, dict):
        try:
            return AccessPolicy.model_validate(previous_record)
        except (ValidationError, ValueError):
            return None
    return None


class UpdateWorkloadAccessRequest(AccessIntake):
    """``PATCH /api/workloads/{pid}/access`` (admin-only, audited): the operator's answer to ACCESS_POLICY_INCOMPLETE /
    ACCESS_POLICY_REQUIRED for an existing workload, and the M3 backfill tool (``source="migration"``)."""

    source: Literal["operator_hitl", "migration"] = Field(default="operator_hitl")
    reason: Optional[StrictStr] = Field(default=None, max_length=500, description="Why the access record is set (audit log)")
    confirm_widening: StrictBool = Field(
        default=False,
        description="L19-F4: must be true when the new record is wider than the current one (a less restrictive "
                    "mode, a member that was not there, or no current record). A widening is audited with "
                    "widening=true and forces plan approval on the workload's next run.",
    )


class CreateWorkloadRequest(BaseModel):
    product_id: str = Field(description="Unique workload identifier/slug, e.g. payment-service")
    title: Optional[str] = Field(default=None, description="Human readable workload title")
    description: Optional[str] = Field(default="", description="High level summary of the workload")
    budget_ceiling_monthly_usd: Optional[float] = Field(
        default=None,
        description="Monthly budget ceiling in USD (default: the platform setting finops.default_monthly_budget_usd)")
    github_repo: Optional[str] = Field(default=None, description="Target GitHub repository in owner/repo format")
    vcs_provider: Optional[str] = Field(default=None, description="Target VCS provider: 'GITHUB' or 'SERVERLESS_GIT' (defaults to platform setting)")
    folder_id: Optional[str] = Field(default=None, description="Target GCP folder ID for vending")
    iac_engine: Optional[str] = Field(default=None, description="IaC engine to use: TERRAFORM or OPENTOFU (defaults to platform setting)")
    target_branch: Optional[str] = Field(
        default=None,
        description="Primary Git branch. Omitted or empty: the workload's recorded branch on a re-create, else "
                    "Settings > Default GitHub Branch (FD-4CI-b-R1). Given: it must be a plain Git branch name (the "
                    "same check as the setting; 'HEAD' is refused), else 422 (FD-4CI-b-R1-API).")

    @field_validator("target_branch")
    @classmethod
    def _target_branch_is_a_branch_name(cls, value: Optional[str]) -> Optional[str]:
        # FD-4CI-b-R1-API: only an explicit value is checked. None / "" keep today's resolution in the route (recorded
        # branch -> setting -> main); a recorded branch is never re-checked here. Never rewritten (no strip).
        if value and not is_branch_name(value):
            raise ValueError(branch_name_refusal(
                "target_branch", value, "the workload's recorded branch or Settings > Default GitHub Branch"))
        return value
    require_human_code_review: bool = Field(default=True, description="Requires manual review before merging Pull Requests into main (Auto-Merge disabled)")
    auto_merge: Optional[bool] = Field(default=None, description="Enables autonomous merge into main without manual review")
    require_plan_approval: Optional[bool] = Field(default=None, description="Requires manual review and approval of the architectural plan before Developer Agent code generation")
    spec_content: Optional[str] = Field(default="", description="Full technical specification, API requirements, and acceptance criteria")
    # compliance-profile-explicit: the workload's compliance profile, chosen explicitly (never inferred from the spec).
    # Unset = STANDARD unless the parent folder is an Assured Workloads folder. An unknown value is a 422.
    compliance_profile: Optional[ComplianceProfile] = Field(
        default=None,
        description="Compliance profile: STANDARD, HIPAA, FEDRAMP_MODERATE, FEDRAMP_HIGH, CJIS, EU_REGIONS_AND_SUPPORT or PCI_DSS",
    )

    @field_validator("compliance_profile", mode="before")
    @classmethod
    def _empty_profile_is_unset(cls, value: Any) -> Any:
        # The create form's "Standard (default)" option sends "". Only the empty string means unset; every other value
        # must match the enum exactly (pydantic answers 422 otherwise).
        return None if value == "" else value
    # GHA-DEPLOY-SWITCH (register row GHA-DEPLOY-SWITCH): GitHub workloads only.
    github_actions_deploy: Optional[bool] = Field(
        default=None,
        description="GitHub workloads only: the GitHub Actions deploy path (the generated "
                    ".github/workflows/deploy-<service>.yml deploying with sa-gh-deployer through Workload Identity "
                    "Federation). Unset on a new workload: on. false: no workflow files and no WIF pool, provider or "
                    "deployer, so every deploy goes through the platform's pipeline. A Serverless Git workload refuses "
                    "false (422 GHA_DEPLOY_SWITCH_NOT_GITHUB). An existing workload keeps its value; it is changed with "
                    "PATCH /api/workloads/{product_id}/github-actions-deploy (administrator, audited).")
    # FD-7M-a (owner 10-31): the one region the workload deploys into, from Settings > Approved Deployable Regions.
    # Recorded on workloads/{pid}.region at creation and never changed. Unset = Settings default region.
    region: Optional[str] = Field(
        default=None,
        description="Region the workload deploys into: one of the approved deployable regions (Settings). Omitted or "
                    "empty: the default region. Any other value is refused (422 REGION_NOT_APPROVED); a regulated "
                    "compliance profile that does not allow it is refused (422 REGION_PROFILE_CONFLICT); an existing "
                    "workload keeps its recorded region (409 REGION_CHANGE_REFUSED for another one).",
    )

    @field_validator("region", mode="before")
    @classmethod
    def _empty_region_is_unset(cls, value: Any) -> Any:
        # Only the empty string means unset; every other value is checked against the approved list by the route.
        return None if value == "" else value
    # --- Express Mode Fields ---
    creation_mode: Optional[str] = Field(default="AGENT", description="Workload creation mode: 'AGENT' or 'EXPRESS'")
    module_instances: Optional[List[ModuleInstanceConfig]] = Field(default_factory=list, description="Selected modules and instances for Express mode")
    include_vpc: Optional[bool] = Field(default=False, description="Whether to include Enterprise VPC networking in Express mode")
    # EXP-7 (register row, owner 10-19): an Express deploy refuses a plan that deletes or replaces a resource already
    # in state (DESTROY_REQUIRES_APPROVAL, listing the addresses). The operator approves by re-submitting with exactly
    # those addresses here. Express only (a non-empty list on an Agent request is a 422).
    approved_removals: Optional[List[str]] = Field(
        default=None, max_length=500,
        description="Express only: resource addresses the operator approves for deletion/replacement on this deploy "
                    "(must equal exactly the addresses a DESTROY_REQUIRES_APPROVAL refusal listed)",
    )
    # --- FinOps Breach Policy ---
    budget_breach_policy: Optional[BudgetBreachPolicy] = Field(
        default=None,
        description="Action taken when workload exceeds 100% budget ceiling (defaults to platform setting).",
    )

    @field_validator("budget_breach_policy", mode="before")
    @classmethod
    def _empty_breach_policy_is_platform_default(cls, value: Any) -> Any:
        # FD-4CI-b (10): the create form's "Platform Default" option sends "". Only the empty string means unset (the
        # platform's finops.default_breach_policy is then stored); every other value must match the enum exactly.
        return None if value == "" else value
    # --- Sandbox Lifespan Fields ---
    is_sandbox: Optional[bool] = Field(
        default=None,
        description="Designates workload as an ephemeral sandbox environment with automated 30-day lifecycle expiration. If None, auto-detected from spec_content.",
    )
    sandbox_ttl_days: Optional[int] = Field(
        default=30,
        description="Lifecycle duration in days before automatic decommissioning (defaults to 30).",
    )
    # --- Lane 19 L19-11: who may use the app (stored as workloads/{pid}.access) ---
    access: Optional[AccessIntake] = Field(
        default=None,
        description="Who may use the generated app. Unset on a NEW workload: the platform default record "
                    "(OSS-D23: PRIVATE_IAP, Google sign-in through IAP, listing the verified signed-in submitter; "
                    "with none, nobody, and the build stops with ACCESS_POLICY_INCOMPLETE until an administrator "
                    "lists them via PATCH /api/workloads/{pid}/access). "
                    "Unset on an existing workload: its record is left as it is. Public is mode PUBLIC_APP here.",
    )


class UpdateGitHubActionsDeployRequest(BaseModel):
    """GHA-DEPLOY-SWITCH: PATCH /api/workloads/{product_id}/github-actions-deploy (administrator, audited)."""
    enabled: bool = Field(description="true: the GitHub Actions deploy path is on (the default). false: no workflow "
                                      "files and no WIF pool, provider or sa-gh-deployer after the next deploy.")


class UpdateWorkloadPoliciesRequest(BaseModel):
    code_freeze: Optional[bool] = Field(default=None, description="Master freeze toggle preventing all autonomous agent code changes or PRs")
    sre_auto_healing_enabled: Optional[bool] = Field(default=None, description="Enables autonomous SRE hotfix workflow execution on runtime crashes")
    refactor_scanner_enabled: Optional[bool] = Field(default=None, description="Enables automated PR creation from nightly code and security scans")
    require_human_code_review: Optional[bool] = Field(default=None, description="Requires manual review on GitHub before merging Pull Requests into main")
    auto_merge: Optional[bool] = Field(default=None, description="Enables autonomous squash merge into main without manual review")
    require_plan_approval: Optional[bool] = Field(default=None, description="Toggle architectural plan approval requirement for this workload")
    budget_breach_policy: Optional[BudgetBreachPolicy] = Field(default=None, description="Action taken when workload exceeds 100% budget ceiling")


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REWORK = "REWORK"
    # FD-4N (red-team H6): decision state machine. DECIDING is the compare-and-set claim; the two *_FAILED
    # states are re-decidable (operator fixes the cause, then decides again).
    DECIDING = "DECIDING"
    MERGE_FAILED = "MERGE_FAILED"
    CALLBACK_FAILED = "CALLBACK_FAILED"
    # Lane 18 S2: a budget-breach DECOMMISSION that vending refused or failed (nothing changed; re-decidable).
    EXECUTION_FAILED = "EXECUTION_FAILED"
    # FD-4BE: the approved merge was refused because main moved since the branch was cut (git server FF-only 409)
    # and the waiting run was ended (MERGE_FAILED / MAIN_MOVED callback delivered). Terminal: never re-decidable.
    MAIN_MOVED = "MAIN_MOVED"
    # GH-MERGE-CALLBACK (owner 10-27): the approved GitHub merge was attempted and failed, and the waiting run was
    # ended (MERGE_FAILED / RELEASE_FAILED callback delivered). Terminal: never re-decidable.
    RELEASE_FAILED = "RELEASE_FAILED"


class ApprovalType(str, Enum):
    PULL_REQUEST = "PULL_REQUEST"
    PR_MERGE = "PR_MERGE"
    ARCHITECTURAL_PLAN = "ARCHITECTURAL_PLAN"
    BUDGET_CEILING = "BUDGET_CEILING"
    BUDGET_BREACH = "BUDGET_BREACH"
    BUDGET_BREACH_REMEDIATION = "BUDGET_BREACH_REMEDIATION"
    # Owner decision 10-18 (row CP-11): an admin approves downgrading a stored regulated compliance profile.
    COMPLIANCE_PROFILE_DOWNGRADE = "COMPLIANCE_PROFILE_DOWNGRADE"
    # APPROVAL-CONSUME-VIA-VENDING (owner 11-07): an MCP server asks an administrator to approve one exact action
    # (HELM_UNINSTALL, AGENT_ENGINE_DEPLOY, DATASTORE_CREATE); approving mints a bound single-use approval.
    MCP_ACTION = "MCP_ACTION"


class ApprovalRequestRecord(BaseModel):
    approval_id: str
    approval_type: ApprovalType = ApprovalType.PULL_REQUEST
    product_id: str
    trace_id: str
    cost_delta_monthly: str
    risk_assessment: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: str
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    decision_reason: Optional[str] = None
    plan_markdown: Optional[str] = None
    plan_file_path: Optional[str] = None
    task_dag: Optional[Any] = None
    compliance_summary: Optional[str] = None
    rework_cycle: Optional[int] = 0
    feedback: Optional[str] = None
    target_project_id: Optional[str] = None
    current_spend_usd: Optional[float] = None
    budget_ceiling_usd: Optional[float] = None
    buffer_ceiling_usd: Optional[float] = None
    projected_monthly_spend_usd: Optional[float] = None
    quarantined_resources: List[str] = Field(default_factory=list)
    snapshot_id: Optional[str] = None
    failure_reason: Optional[str] = Field(default=None, description="FD-4N: why a decision ended in MERGE_FAILED / CALLBACK_FAILED")
    error_class: Optional[str] = Field(default=None, description="FD-4BE: typed failure class of the decision (MAIN_MOVED)")
    # CP-11: the compliance profile transition a COMPLIANCE_PROFILE_DOWNGRADE card asks for.
    from_profile: Optional[str] = None
    to_profile: Optional[str] = None
    # Code RT F6: what an APPROVED decision merges (PR approvals only), shown on the approval card.
    github_repo: Optional[str] = Field(default=None, description="Repository the merge targets (workloads/{product_id}.github_repo)")
    branch_name: Optional[str] = Field(default=None, description="Approved branch")
    pr_number: Optional[int] = Field(default=None, description="GitHub PR number recorded by the gateway release step (None: Serverless Git, or a legacy record that cannot merge)")
    vcs_provider: Optional[str] = Field(default=None, description="GITHUB or SERVERLESS_GIT (from the workload doc)")
    # L19-F4 RT R2: a plan approval forced by a widened access record shows what is widened (pre-build gate reason
    # ACCESS_WIDENED; values copied by the gateway into approval_requests/{id}.access_under_review).
    gate_reasons: List[str] = Field(default_factory=list)
    access_widened: bool = False
    access_mode_before: Optional[str] = Field(default=None, description="Mode of the last approved record (None: no record)")
    access_mode_after: Optional[str] = Field(default=None, description="Mode the build will use")
    access_added_members: Optional[List[str]] = Field(
        default_factory=list, description="Members not in the last approved record (None: unknown, the copy is malformed)")
    access_members_now: List[str] = Field(default_factory=list, description="Members of the record the build will use")
    # ACCESS-INTERNAL-SERVICE-ADVISORY: the compliance stage's typed access warnings on a plan approval card
    # (`ACCESS.INTERNAL_SERVICE_PUBLIC`: a Cloud Run service only Pub/Sub push calls is public in a Public app).
    access_advisories: List[Dict[str, Any]] = Field(
        default_factory=list, description="Typed access warnings copied by the gateway (code, service, message)")
    access_advisories_omitted: int = Field(
        default=0, description="Further services in the same situation, counted by the gateway (the list is capped)")
    access_advisories_unreadable: bool = Field(
        default=False, description="The card's access warnings are malformed: shown as unreadable, never as none")
    # SECRET-INITIAL-VERSION: the plan's Secret Manager secrets the platform creates without a value
    # (`SECRET.OPERATOR_VALUE_REQUIRED` / `SECRET.VALUE_SOURCE_UNSTATED`), copied by the pre-build gate.
    secret_advisories: List[Dict[str, Any]] = Field(
        default_factory=list, description="Typed secret warnings copied by the gateway (code, secret, message)")
    secret_advisories_omitted: int = Field(
        default=0, description="Further secrets in the same situation, counted by the gateway (the list is capped)")
    secret_advisories_unreadable: bool = Field(
        default=False, description="The card's secret warnings are malformed: shown as unreadable, never as none")
    # FD-4CI-b-R2: the FinOps Agent Model's recommendation on a budget-breach card (apps/finops-enforcer/finops_advisor.py)
    finops_recommendation: Optional[str] = Field(default=None, description="Plain-text recommendation (READY only)")
    finops_recommendation_status: Optional[str] = Field(default=None, description="READY or UNAVAILABLE; None: none requested")
    finops_recommendation_note: Optional[str] = Field(default=None, description="Typed reason when UNAVAILABLE")
    finops_recommendation_model: Optional[str] = Field(default=None, description="Model id that answered")
    finops_recommendation_usage: Optional[Dict[str, Any]] = Field(default=None, description="Tokens and USD cost of the call")
    # APPROVAL-CONSUME-VIA-VENDING: what an MCP_ACTION card asks for, and the approval an APPROVED decision minted.
    mcp_action: Optional[str] = Field(default=None, description="HELM_UNINSTALL, AGENT_ENGINE_DEPLOY or DATASTORE_CREATE")
    mcp_project_id: Optional[str] = Field(default=None, description="Workload project named by the requesting MCP server")
    mcp_binding: Dict[str, str] = Field(default_factory=dict, description="Exact tool arguments the approval is bound to")
    mcp_binding_digest: Optional[str] = Field(default=None, description=(
        "SHA-256 of the displayed mcp_binding, computed by the CC (never the stored field); the decision echoes it"))
    mcp_card_malformed: bool = Field(default=False, description="The card's arguments are invalid: reject only")
    mcp_details: Dict[str, Any] = Field(default_factory=dict, description="Display-only context from the MCP server")
    mcp_requested_by: Optional[str] = Field(default=None, description="Requesting MCP server")
    mcp_approval_id: Optional[str] = Field(default=None, description=(
        "Minted single-use approval id: in the decision answer, and to administrators from the guard database; "
        "never stored on the card"))
    mcp_approval_status: Optional[str] = Field(default=None, description="Status of the minted approval (administrators)")
    mcp_approval_expires_at: Optional[str] = Field(default=None, description="Expiry of the minted approval")


class ApprovalDecisionRequest(BaseModel):
    decision: ApprovalStatus = ApprovalStatus.APPROVED
    action: Optional[str] = Field(default=None, description="HITL action: INCREASE_BUDGET, RESTORE_BUFFER, MAINTAIN_QUARANTINE, DECOMMISSION")
    new_budget_usd: Optional[float] = Field(default=None, description="New monthly budget ceiling if action is INCREASE_BUDGET")
    reason: Optional[str] = None
    feedback: Optional[str] = None
    # APPROVAL-CONSUME-VIA-VENDING RT F1: what the administrator saw on an MCP_ACTION card; the decision is refused
    # (409 APPROVAL_CARD_CHANGED) when the card changed since it was displayed.
    mcp_action: Optional[str] = None
    mcp_binding_digest: Optional[str] = None


class EmergencyStopRequest(BaseModel):
    activate: bool = Field(description="True to engage emergency stop and cancel all agents; False to resume")
    reason: Optional[str] = Field(default="Operator manual override", description="Audit reason for triggering kill switch")


class EmergencyStopResponse(BaseModel):
    emergency_stop_active: bool
    status: str
    activated_at: Optional[str] = None
    activated_by: Optional[str] = None
    reason: Optional[str] = None
    workflows_cancelled_count: int = 0
    workloads_frozen_count: int = 0
    # FD-4CI-b #1 (owner 10-21): engage snapshots each workload's pre-engage freeze/SRE state; resume restores it.
    # All optional/defaulted so existing clients keep working.
    stop_id: Optional[str] = Field(default=None, description="Identifier of the engaged stop (kept across a repeated engage)")
    workloads_skipped_decommissioned_count: int = Field(default=0, description="Engage: DECOMMISSIONED/DELETED workloads left untouched")
    workloads_snapshot_kept_count: int = Field(default=0, description="Engage: workloads that already carried a snapshot (kept, not overwritten)")
    workloads_restored_count: int = Field(default=0, description="Resume: workloads whose snapshot was applied and removed")
    workloads_operator_override_count: int = Field(default=0, description="Resume: workloads where an operator changed freeze/healing during the stop (current value kept)")
    workloads_without_snapshot_count: int = Field(default=0, description="Resume: workloads with no snapshot (not modified)")
    workloads_malformed_snapshot_count: int = Field(default=0, description="Resume: unreadable snapshots removed; those workloads keep their current freeze/SRE values")
    workloads_failed_count: int = Field(default=0, description="Workloads whose Firestore write failed (engage: may not be frozen; resume: still frozen, snapshot kept). GET: failures of the last resume while the switch is off (Retry restore)")
    failed_workloads: List[str] = Field(default_factory=list, description="product_ids counted in workloads_failed_count")
    errors: List[str] = Field(default_factory=list, description="Firestore errors met while engaging or resuming")
    # SAT-43: the running workflow executions engage tried to cancel (Workflows REST API), with typed outcomes. Never
    # "OK" unless every platform workflow was listed and every listed execution was cancelled or had already ended.
    workflows_cancel_status: Optional[str] = Field(default=None, description="Engage (and GET while engaged): OK, or why running workflow executions were not all cancelled: WORKFLOW_CANCEL_NOT_PERMITTED, WORKFLOW_CANCEL_UNCONFIGURED, WORKFLOW_LIST_FAILED, WORKFLOW_CANCEL_FAILED")
    workflows_cancel_detail: Optional[str] = Field(default=None, description="One line on what was not cancelled (null when OK)")
    workflows_already_finished_count: int = Field(default=0, description="Engage: listed executions that had ended before the cancel reached them")
    workflows_cancel_failed_count: int = Field(default=0, description="Engage: listed executions that could not be cancelled (may still be running)")
    workflow_list_failures: List[Dict[str, Any]] = Field(default_factory=list, description="Engage: platform workflows whose active executions could not be listed: {workflow, reason, detail}")
    workflow_cancel_results: List[Dict[str, Any]] = Field(default_factory=list, description="Engage: one entry per listed execution: {name, workflow, outcome (CANCELLED, ALREADY_FINISHED, FAILED), reason, detail, state}")


class ChatQueryRequest(BaseModel):
    message: str
    conversation_history: Optional[List[Dict[str, str]]] = Field(default_factory=list)


class ChatResponse(BaseModel):
    response_text: str
    actions_suggested: List[str] = Field(default_factory=list)
    pending_approvals: List[Dict[str, Any]] = Field(default_factory=list)


class ArchitectureDiagramResponse(BaseModel):
    product_id: str
    mermaid_code: str
    security_boundaries: List[str] = Field(default_factory=list)
    services_count: int = Field(default=0)


class DispatchRefactorRequest(BaseModel):
    target_repo_or_dir: Optional[str] = "."
    rule_category: Optional[str] = "ALL"


class DeployedResource(BaseModel):
    resource_type: str = Field(description="Terraform resource type, e.g. google_cloud_run_v2_service")
    resource_name: str = Field(description="Logical resource name defined in HCL")
    resource_id: Optional[str] = Field(default=None, description="Actual cloud resource ID or URI")
    provider: Optional[str] = Field(default=None, description="Provider identifier")
    module: Optional[str] = Field(default=None, description="Module hierarchy path")
    mode: Optional[str] = Field(default="managed", description="Resource mode (managed or data)")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Key attributes extracted from state")


class WorkloadDetailsResponse(BaseModel):
    product_id: str
    project_id: str
    github_repo: Optional[str] = Field(default=None, description="GitHub repository in owner/repo format")
    vcs_provider: Optional[str] = Field(default="GITHUB", description="VCS provider: GITHUB or SERVERLESS_GIT")
    git_clone_url: Optional[str] = Field(default=None, description="Direct clone URL for git repository")
    git_clone_url_error: Optional[Literal["GIT_SERVER_URL_UNKNOWN"]] = Field(
        default=None,
        description="FALLBACK-URLS: why git_clone_url is empty for a Serverless Git workload (the git server URL is "
                    "not known from GIT_SERVER_URL, governance.git_server_url or the Cloud Run Admin API). Never a "
                    "guessed URL.")
    default_branch: Optional[str] = Field(default="main", description="Primary repository branch")
    folder_id: Optional[str] = Field(default=None, description="GCP folder ID where workload is provisioned")
    folder_name: Optional[str] = Field(default=None, description="Human-readable folder display name")
    status: str
    budget_ceiling_monthly_usd: float
    current_spend_usd: float = Field(default=0.0)
    projected_monthly_spend_usd: Optional[float] = Field(default=None, description="Extrapolated end-of-month spend run rate based on day-of-month progress")
    spend_last_updated_at: Optional[str] = Field(default=None, description="Timestamp of the most recent FinOps spend calculation")
    is_overrun_projected: bool = Field(default=False, description="True if projected monthly spend exceeds the budget ceiling")
    spend_source: Optional[str] = Field(default=None, description="Spend data origin: GCP_BILLING_EXPORT or ESTIMATED_ACTIVE_ACCRUAL")
    cached_hourly_burn_usd: Optional[float] = Field(default=None, description="Cached hourly burn rate in USD calculated from deployed infrastructure")
    service_url: Optional[str] = None
    service_url_unknown_reason: Optional[str] = Field(default=None, description="Typed reason the last deploy could not read its service URL (the URL is then unknown, never guessed)")
    created_at: Optional[str] = None
    description: Optional[str] = None
    state_source: Optional[str] = None
    terraform_version: Optional[str] = None
    serial: Optional[int] = None
    resources_count: int = 0
    resources: List[DeployedResource] = Field(default_factory=list)
    outputs: Dict[str, Any] = Field(default_factory=dict)
    outputs_withheld_reason: Optional[str] = Field(default=None, description="RT14-03: OUTPUTS_MANAGER_ONLY when the "
                                                   "workload has OpenTofu outputs and the caller is a VIEWER (outputs "
                                                   "go to workload managers and administrators only)")
    is_castor: bool = Field(default=False, description="True if this workload is the StackVend platform itself, False for other workloads")
    iac_engine: Optional[str] = Field(default="TERRAFORM", description="IaC engine used for this workload: TERRAFORM or OPENTOFU")
    region: Optional[str] = Field(default=None, description="FD-7M-a: the region recorded at creation. None: a workload "
                                                            "created before approved regions; it follows Settings > "
                                                            "Default Workload Region.")
    code_freeze: bool = Field(default=False, description="Master freeze toggle preventing all autonomous agent code changes or PRs")
    github_actions_deploy: Optional[bool] = Field(default=True, description="GHA-DEPLOY-SWITCH: the GitHub Actions deploy path (GitHub workloads; missing = on). None: the stored value is not true or false")
    sre_auto_healing_enabled: bool = Field(default=True, description="Enables autonomous SRE hotfix workflow execution on runtime crashes")
    refactor_scanner_enabled: bool = Field(default=True, description="Enables automated PR creation from nightly code and security scans")
    require_human_code_review: bool = Field(default=True, description="Requires manual review before merging Pull Requests into main (Auto-Merge disabled)")
    auto_merge: bool = Field(default=False, description="True if autonomous auto-merge into main is enabled without manual review")
    require_plan_approval: bool = Field(default=False, description="Requires manual review and approval of the architectural plan before Developer Agent code generation")
    budget_breach_policy: Optional[str] = Field(default="AUTONOMOUS_SCALE_TO_ZERO", description="Breach policy: AUTONOMOUS_SCALE_TO_ZERO, ALERT_ONLY, HITL_CONFIRMATION_REQUIRED, NUCLEAR_UNLINK_BILLING")
    buffer_ceiling_usd: Optional[float] = Field(default=None, description="Temporary overrun buffer ceiling in USD (+15%)")
    decommissioned_at: Optional[str] = None
    decommissioned_by: Optional[str] = None
    archived_at: Optional[str] = None
    archived_by: Optional[str] = None
    last_active_project_id: Optional[str] = None
    last_iac_upgrade_at: Optional[str] = Field(default=None, description="Timestamp of the most recent IaC module/bundle upgrade")
    last_iac_upgrade_by: Optional[str] = Field(default=None, description="User or service who triggered the last IaC upgrade")
    last_iac_upgrade_status: Optional[str] = Field(default=None, description="Status of the last IaC upgrade (SUCCESS, FAILED, ROLLED_BACK)")
    iac_drift_detected: Optional[bool] = Field(default=None, description="True if any vendored modules have newer upstream releases or content drift")
    iac_drift_count: Optional[int] = Field(default=0, description="Count of outdated or drifted vendored modules")
    network: Optional[Dict[str, Any]] = Field(default=None, description="Assigned VPC and IPAM network configuration")
    file_attribution: Optional[Dict[str, str]] = Field(default_factory=dict, description="File-to-subagent persona attribution map")
    iac_intent_warnings: List[Dict[str, Any]] = Field(default_factory=list, description="TI-3i: typed IaC intent entries the last generate-mode build removed as not expressible (IAC.TYPE_NOT_ALLOWED / IAC.MODULE_UNKNOWN)")
    runtime_env_advisories: List[Dict[str, Any]] = Field(default_factory=list, description="RUNTIME-ENV-CONTRACT-CHECK: environment variables a service's code reads that the platform does not set on it (ENV.READ_NOT_PROVIDED), or services whose platform-set variables are not known (ENV.PROVIDED_SET_UNKNOWN); warnings from the last passing build, never block")
    runtime_env_advisories_total: int = Field(default=0, description="RUNTIME-ENV-CONTRACT-CHECK: the number of findings of the last passing build (the list keeps at most 50)")
    # --- Autonomous Sandbox Lifespan Fields ---
    is_sandbox: bool = Field(default=False, description="True if workload is an ephemeral sandbox")
    sandbox_ttl_days: Optional[int] = Field(default=30, description="Configured sandbox lifespan in days")
    sandbox_expires_at: Optional[str] = Field(default=None, description="ISO timestamp when sandbox expires")
    sandbox_days_remaining: Optional[float] = Field(default=None, description="Calculated days remaining before auto-decommissioning")
    sandbox_auto_decommission: bool = Field(default=True, description="True if auto-decommission is active")
    sandbox_designation_source: Optional[str] = Field(default=None, description="How the workload became a sandbox: API_FIELD / OPERATOR_CHECKBOX / OPERATOR_CONFIRMED (explicit) or KEYWORD_DETECTED / none (not auto-deleted until confirmed)")
    sandbox_awaiting_confirmation: bool = Field(default=False, description="True for a sandbox whose designation is not explicit: it is deleted only after an ADMIN confirms it (POST /api/workloads/{id}/sandbox/confirm)")
    ttl_authority: Optional[str] = Field(default=None, description="VENDING_PROVENANCE (vending enforces the expiry) or LEDGER_DISPLAY_ONLY (the countdown is informational; nothing auto-deletes the project)")
    sandbox_decommission_status: Optional[str] = Field(default=None, description="SCHEDULED, EXTENDED, EXPIRATION_IMMINENT, DEFERRED_ACTIVE_PIPELINE, DEFERRED_PENDING_REVIEW, GUARD_REFUSED (sweep guard refused the delete), DECOMMISSION_FAILED (CRM delete failed), EXPIRED, DECOMMISSIONED, or PROMOTED")
    cumulative_lifespan_days: int = Field(default=30, description="Total cumulative days workload has run as a sandbox")
    extension_count: int = Field(default=0, description="Number of times lifecycle extension was granted")
    max_extensions_allowed: int = Field(default=3, description="Maximum number of lifecycle extensions allowed")
    max_cumulative_days_allowed: int = Field(default=90, description="Maximum cumulative lifespan days allowed")
    creator_email: Optional[str] = Field(default=None, description="Email of the creator / owner for notifications")
    # COMPLIANCE-BASELINE-LABEL (owner 10-27): display only (apps/control-center/compliance_label.py).
    compliance_label: Optional[str] = Field(default=None, description="Standard / 'Compliance: <regime> (Assured Workloads)' (profile from the folder's Assured Workloads regime) / 'Controls: <regime> baseline (not a compliance environment)'")
    compliance_label_kind: Optional[str] = Field(default=None, description="STANDARD, COMPLIANCE_ENVIRONMENT or CONTROLS_BASELINE")


class FeatureRequestPriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FeatureChangeType(str, Enum):
    FEATURE_ENHANCEMENT = "FEATURE_ENHANCEMENT"
    BUG_FIX = "BUG_FIX"
    INFRASTRUCTURE_REFACTOR = "INFRASTRUCTURE_REFACTOR"
    SECURITY_UPDATE = "SECURITY_UPDATE"


class CreateFeatureRequest(BaseModel):
    title: str = Field(description="Short descriptive title of the feature request")
    description: str = Field(description="Detailed functional requirements and change specification")
    change_type: FeatureChangeType = Field(default=FeatureChangeType.FEATURE_ENHANCEMENT)
    priority: FeatureRequestPriority = Field(default=FeatureRequestPriority.MEDIUM)
    target_components: Optional[str] = Field(default="All Components", description="Target services, endpoints, or infrastructure modules to modify")
    acceptance_criteria: Optional[str] = Field(default="", description="Specific acceptance criteria or test verification steps")


class FeatureRequestRecord(BaseModel):
    request_id: str
    product_id: str
    project_id: str
    title: str
    description: str
    change_type: FeatureChangeType
    priority: FeatureRequestPriority
    target_components: str
    acceptance_criteria: Optional[str] = ""
    status: str = Field(default="PENDING_TRIAGE")
    submitted_by: str
    created_at: str
    channel: str = Field(default="CONTROL_CENTER_UI")
    doc_url: Optional[str] = Field(default=None, description="Direct web link to source Google Doc if ingested from Drive")
    spec_doc_id: Optional[str] = Field(default=None, description="Google Drive file ID if applicable")
    implementation_plan: Optional[str] = Field(default=None, description="Full technical implementation plan text or Markdown")
    source_channel: Optional[str] = Field(default=None, description="Origin channel e.g. google_docs, control_center_ui")
    task_dag: Optional[List[Dict[str, Any]]] = Field(default=None, description="Decomposed tasks DAG if already planned")
    plan_filename: Optional[str] = Field(default=None, description="Filename of the plan markdown in docs/planning/, e.g., 2026-09-06-feat-auth.md")
    plan_file_path: Optional[str] = Field(default=None, description="Repository-relative path, e.g., docs/planning/2026-09-06-feat-auth.md")
    plan_github_url: Optional[str] = Field(default=None, description="Direct URL to view the plan markdown on GitHub")


class LogEntryRecord(BaseModel):
    timestamp: str = Field(description="ISO timestamp of log entry")
    severity: str = Field(default="INFO", description="Log severity level: DEBUG, INFO, WARNING, ERROR, CRITICAL")
    service_name: Optional[str] = Field(default="", description="Cloud Run service or workload microservice name")
    resource_type: Optional[str] = Field(default="cloud_run_revision", description="GCP Resource Type")
    message: str = Field(description="Formatted log message or payload text")
    json_payload: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Structured log attributes")
    insert_id: Optional[str] = None
    log_source: Optional[str] = Field(default=None, description="RT14-31: WORKLOAD (the workload's child project), "
                                      "PLATFORM_PIPELINE (platform services' logs about this workload, host project) "
                                      "or PLATFORM (host-wide platform logs)")


class WorkloadLogsResponse(BaseModel):
    product_id: str
    project_id: str
    total_count: int = 0
    log_filter: str = ""
    logs: List[LogEntryRecord] = Field(default_factory=list)
    source_errors: List[Dict[str, Any]] = Field(default_factory=list, description="RT14-31: one {source, project, "
                                                "code, detail} per log source that could not be read")


class TaskSourceType(str, Enum):
    FEATURE_REQUEST = "FEATURE_REQUEST"
    SRE_INCIDENT = "SRE_INCIDENT"
    GITHUB_CODE_ISSUE = "GITHUB_CODE_ISSUE"
    INFRASTRUCTURE_PLAN = "INFRASTRUCTURE_PLAN"
    NEW_WORKLOAD_PROVISION = "NEW_WORKLOAD_PROVISION"
    CONTINUOUS_SCAN = "CONTINUOUS_SCAN"


class AgentTaskStatus(str, Enum):
    IN_PROGRESS = "IN_PROGRESS"
    QUEUED = "QUEUED"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class AgentTaskRecord(BaseModel):
    task_id: str = Field(description="Unique task tracking ID")
    agent_id: str = Field(description="Target agent key: architect, developer, gcp-devops, qa-reviewer, release-engineer, finops, sre")
    workload_id: str = Field(description="Associated workload product ID")
    project_id: str = Field(description="Associated Google Cloud Project ID")
    github_repo: Optional[str] = Field(default=None, description="Target GitHub repository")
    title: str = Field(description="Short descriptive task title")
    description: str = Field(description="Task requirements or error specification")
    source_type: TaskSourceType = Field(default=TaskSourceType.FEATURE_REQUEST)
    priority: FeatureRequestPriority = Field(default=FeatureRequestPriority.MEDIUM)
    status: AgentTaskStatus = Field(default=AgentTaskStatus.QUEUED)
    created_at: str = Field(description="ISO creation timestamp")
    updated_at: Optional[str] = None
    trace_id: Optional[str] = None


class AgentStatusSummary(BaseModel):
    agent_id: str = Field(description="Agent key")
    name: str = Field(description="Agent display name")
    role_title: str = Field(description="Functional operational role")
    avatar_icon: str = Field(description="Icon or avatar emoji")
    status: str = Field(default="IDLE", description="Operational status: ACTIVE, IDLE, WAITING_APPROVAL, BLOCKED")
    tooling: List[str] = Field(default_factory=list, description="Primary MCP tool servers and GCP APIs")
    current_task: Optional[AgentTaskRecord] = Field(default=None, description="Task currently in execution")
    backlog_count: int = Field(default=0, description="Number of items in agent backlog")
    backlog: List[AgentTaskRecord] = Field(default_factory=list, description="Queued task items for this agent")
    completed_count: int = Field(default=0, description="Number of completed tasks")


class ToolServerSummary(BaseModel):
    server_id: str = Field(description="Unique tool server identifier")
    name: str = Field(description="Human readable title")
    role_description: str = Field(description="Core infrastructure capability")
    service_name: str = Field(description="Cloud Run microservice identifier")
    icon: str = Field(default="⚙️")
    status: str = Field(default="HEALTHY", description="Operational status: HEALTHY, DEGRADED, BUSY")
    operations_count: int = Field(default=0, description="Total operations executed")
    recent_operations: List[Dict[str, Any]] = Field(default_factory=list, description="Recent vending, terraform, infracost, or git actions")


class PipelineOverviewResponse(BaseModel):
    total_active_tasks: int = 0
    total_backlog: int = 0
    total_completed: int = 0
    agents_count: int = 9
    is_placeholder: bool = Field(default=False, description="True if Firestore collections are empty/missing and baseline placeholder data is shown")
    agents: List[AgentStatusSummary] = Field(default_factory=list)
    tool_servers: List[ToolServerSummary] = Field(default_factory=list)
    recent_intake_stream: List[AgentTaskRecord] = Field(default_factory=list)


# ------------------------------------------------------------------------------
# Cloud Workflows Async Callback Models
# ------------------------------------------------------------------------------
class AsyncJobAck(BaseModel):
    status: str = "ACCEPTED"
    product_id: str
    trace_id: Optional[str] = None
    message: str = "Task dispatched to background worker. Workflow will resume via callback."


class AsyncCallbackPayload(BaseModel):
    status: str = Field(description="SUCCESS or FAILED")
    error: Optional[str] = None
    execution_duration_seconds: Optional[float] = None
    product_id: Optional[str] = None
    trace_id: Optional[str] = None
    outputs: Optional[Dict[str, Any]] = None
    traceback: Optional[str] = None


class AsyncVendingRequest(BaseModel):
    product_id: str
    trace_id: Optional[str] = None
    folder_id: Optional[str] = None
    billing_account_id: Optional[str] = None
    github_owner: Optional[str] = None
    initial_budget: Optional[float] = 40.0
    callback_url: str


class AsyncDeployRequest(BaseModel):
    product_id: str
    trace_id: Optional[str] = None
    hcl_files: Optional[Dict[str, str]] = None
    target_project_id: Optional[str] = None
    callback_url: str


class AsyncQAVerifyRequest(BaseModel):
    product_id: str
    branch_name: str
    trace_id: Optional[str] = None
    callback_url: str


# --- Flight Deck & In-Flight Pipeline Observability Schemas ---

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


class StageExecutionDetail(BaseModel):
    status: str = Field(default="QUEUED", description="QUEUED | IN_FLIGHT | SUCCESS | FAILED | SKIPPED")
    state: Optional[str] = Field(default=None, description="AWAITING_CALLBACK | CALLBACK_DELIVERED | None")
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    summary: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class PipelineExecutionItem(BaseModel):
    trace_id: str = Field(default="")
    product_id: str = Field(default="")
    request_id: Optional[str] = None
    feature_title: Optional[str] = None
    status: str = Field(default="ACTIVE", description="ACTIVE | SUCCEEDED | FAILED")
    current_stage: str = Field(default="ARCHITECT")
    started_at: str = Field(default="")
    completed_at: Optional[str] = None
    elapsed_seconds: Optional[float] = None
    workflow_execution_id: Optional[str] = None
    stages: Dict[str, StageExecutionDetail] = Field(default_factory=dict)
    outputs: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    # STALE-RUN-AUTOFAIL-BOUND (RT F2): the typed reason a run was closed (workflow notify, Flight Deck reconcile or
    # silence rule) and its message.
    error_class: Optional[str] = None
    error_message: Optional[str] = None
    cooldown_state: Optional[Dict[str, Any]] = None
    force_resume: Optional[bool] = None
    # STALE-RUN-AUTOFAIL-BOUND: the last Workflows API state check of a bound run when it failed or reconciled the run
    # ({at, outcome: READ_FAILED | OK | RECONCILED, reason?, detail?, state?}).
    workflow_state_check: Optional[Dict[str, Any]] = None
    # BUILD-ADMISSION-QUEUE (G4): a run that waits for a build slot (status QUEUED): {state, position, ahead, limit,
    # running}; queued_at = when it joined the queue (kept after it starts).
    build_queue: Optional[Dict[str, Any]] = None
    queued_at: Optional[str] = None


class ActiveExecutionsResponse(BaseModel):
    active_executions: List[PipelineExecutionItem] = Field(default_factory=list)
    total_active: int = 0
    # BUILD-ADMISSION-QUEUE (G4): builds waiting for a slot, in queue order, and {limit, running, queued}.
    queued_executions: List[PipelineExecutionItem] = Field(default_factory=list)
    build_queue: Optional[Dict[str, Any]] = None
    latest_completed: Optional[PipelineExecutionItem] = None
    recent_completed: List[PipelineExecutionItem] = Field(default_factory=list)


class FlightDeckResponse(BaseModel):
    execution: PipelineExecutionItem
    live_logs: List[Dict[str, Any]] = Field(default_factory=list)
    live_logs_error: Optional[Dict[str, Any]] = Field(default=None, description="RT14-31: LOGS_UNAVAILABLE detail when "
                                                      "the run's logs could not be read (live_logs is then empty)")


# --- Enterprise Custom Golden Modules Catalog Schemas ---

class CustomModuleSourceType(str, Enum):
    DIRECT_CODE = "DIRECT_CODE"
    REMOTE_GIT = "REMOTE_GIT"
    BUILT_IN = "BUILT_IN"


class CustomModuleCategory(str, Enum):
    NETWORKING = "NETWORKING"
    COMPUTE = "COMPUTE"
    DATABASE = "DATABASE"
    STORAGE = "STORAGE"
    SECURITY = "SECURITY"
    ANALYTICS = "ANALYTICS"
    CUSTOM = "CUSTOM"


class ModuleVariableContract(BaseModel):
    name: str = Field(description="Terraform input variable name")
    type: str = Field(default="string", description="HCL type (string, number, bool, list, map, object)")
    description: Optional[str] = Field(default="", description="Variable description from HCL")
    required: bool = Field(default=True, description="True if no default value is provided")
    default: Optional[Any] = Field(default=None, description="Default value if specified")


class ModuleOutputContract(BaseModel):
    name: str = Field(description="Terraform output name")
    description: Optional[str] = Field(default="", description="Output description from HCL")


class CustomGoldenModuleRecord(BaseModel):
    module_id: str = Field(description="Unique identifier e.g. 'acme-secure-vpc'")
    name: str = Field(description="Human-readable module display name")
    source_type: CustomModuleSourceType = Field(default=CustomModuleSourceType.DIRECT_CODE)
    category: CustomModuleCategory = Field(default=CustomModuleCategory.CUSTOM)
    description: Optional[str] = Field(default="", description="Description of the module purpose")
    
    # Remote Git configuration (when source_type == REMOTE_GIT)
    source_url: Optional[str] = Field(default=None, description="Remote Git URL e.g. https://github.com/acme/tf-modules")
    repo_path: Optional[str] = Field(default="", description="Subdirectory path in repository e.g. 'modules/vpc'")
    version_tag: Optional[str] = Field(default="v1.0.0", description="Git branch or SemVer tag e.g. 'v2.4.1'")
    
    # Direct HCL code payload (when source_type == DIRECT_CODE)
    hcl_files: Dict[str, str] = Field(default_factory=dict, description="Filename to content mapping (main.tf, variables.tf, outputs.tf)")
    
    # Platform override & execution policy
    override_builtin: Optional[str] = Field(default=None, description="Name of built-in module this substitutes e.g. 'vpc'")
    is_heavy_stateful: bool = Field(default=False, description="Whether to route execution to 24h tf-applier Cloud Run Job")
    timeout_minutes: int = Field(default=15, description="Timeout ceiling in minutes for terraform execution")
    
    # Introspected AST schema contracts
    inputs: List[ModuleVariableContract] = Field(default_factory=list)
    variables: List[ModuleVariableContract] = Field(default_factory=list)
    outputs: List[ModuleOutputContract] = Field(default_factory=list)
    
    # Built-in platform status & override indicator
    is_builtin: bool = Field(default=False, description="True for canonical native platform modules")
    overridden_by: Optional[str] = Field(default=None, description="Custom module ID that overrides this native module")

    # Metadata & operational health
    is_active: bool = Field(default=True)
    sync_status: str = Field(default="VERIFIED", description="VERIFIED | ERROR | PENDING")
    error_message: Optional[str] = None
    last_synced_at: Optional[str] = None
    created_by: str = Field(default="admin")
    created_at: str = Field(default="")


class RegisterCustomModuleRequest(BaseModel):
    module_id: str
    name: str
    source_type: CustomModuleSourceType = CustomModuleSourceType.DIRECT_CODE
    category: CustomModuleCategory = CustomModuleCategory.CUSTOM
    description: Optional[str] = ""
    source_url: Optional[str] = None
    repo_path: Optional[str] = ""
    version_tag: Optional[str] = "v1.0.0"
    hcl_files: Dict[str, str] = Field(default_factory=dict)
    override_builtin: Optional[str] = None
    is_heavy_stateful: bool = False
    timeout_minutes: int = 15


class UpdateCustomModuleRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[CustomModuleCategory] = None
    is_active: Optional[bool] = None
    override_builtin: Optional[str] = None
    is_heavy_stateful: Optional[bool] = None
    timeout_minutes: Optional[int] = None
    hcl_files: Optional[Dict[str, str]] = None
    version_tag: Optional[str] = None


class CustomModulesListResponse(BaseModel):
    custom_modules: List[CustomGoldenModuleRecord] = Field(default_factory=list)
    modules: List[CustomGoldenModuleRecord] = Field(default_factory=list)
    builtin_modules_count: int = 19
    total_custom: int = 0


# --- Composite Solution Bundles Schemas ---
try:
    from shared.bundle_schema import (
        CompositeBundleRecord,
        CompositeBundleSourceType,
        RegisterBundleRequest,
        ScanRepositoryBundlesRequest,
        DiscoveredBundleSummary,
        BundleDriftStatusResponse,
        UpdateBundleRequest,
    )
except ImportError:
    try:
        from .shared.bundle_schema import (
            CompositeBundleRecord,
            CompositeBundleSourceType,
            RegisterBundleRequest,
            ScanRepositoryBundlesRequest,
            DiscoveredBundleSummary,
            BundleDriftStatusResponse,
            UpdateBundleRequest,
        )
    except ImportError:
        pass


class CustomBundlesListResponse(BaseModel):
    bundles: List[CompositeBundleRecord] = Field(default_factory=list)
    builtin_count: int = 5
    custom_count: int = 0
    total_bundles: int = 5



# --- Agentic Skills System Schemas ---

class TargetAgentRole(str, Enum):
    ALL_AGENTS = "ALL_AGENTS"
    DEVELOPER_AGENT = "DEVELOPER_AGENT"
    ARCHITECT_AGENT = "ARCHITECT_AGENT"
    COMPLIANCE_AGENT = "COMPLIANCE_AGENT"
    GCP_DEVOPS_AGENT = "GCP_DEVOPS_AGENT"
    QA_AGENT = "QA_AGENT"
    RELEASE_ENGINEER_AGENT = "RELEASE_ENGINEER_AGENT"
    SRE_AGENT = "SRE_AGENT"
    FINOPS_AGENT = "FINOPS_AGENT"
    ASSISTANT = "ASSISTANT"


class SkillSourceType(str, Enum):
    BUILT_IN = "BUILT_IN"
    CUSTOM = "CUSTOM"


class AgentSkillRecord(BaseModel):
    skill_id: str = Field(description="Unique kebab-case identifier, e.g. 'gcp-direct-iap'")
    name: str = Field(description="Human-readable title e.g. 'Cloud Run Direct IAP & SSO'")
    source_type: SkillSourceType = Field(default=SkillSourceType.CUSTOM)
    target_agent: TargetAgentRole = Field(default=TargetAgentRole.DEVELOPER_AGENT)
    description: str = Field(default="", description="Summary of skill purpose")
    trigger_keywords: List[str] = Field(default_factory=list, description="Keywords that activate this skill")
    always_active: bool = Field(default=False, description="If true, always included for the target agent")
    instructions_markdown: str = Field(description="Complete SKILL.md prompt instructions and code examples")
    
    # Governance & metadata
    is_builtin: bool = Field(default=False)
    is_active: bool = Field(default=True)
    created_by: str = Field(default="admin")
    created_at: str = Field(default="")
    updated_at: Optional[str] = None


class CreateSkillRequest(BaseModel):
    skill_id: str
    name: str
    target_agent: TargetAgentRole = TargetAgentRole.DEVELOPER_AGENT
    description: str = ""
    trigger_keywords: List[str] = Field(default_factory=list)
    always_active: bool = False
    instructions_markdown: str


class UpdateSkillRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    target_agent: Optional[TargetAgentRole] = None
    trigger_keywords: Optional[List[str]] = None
    always_active: Optional[bool] = None
    instructions_markdown: Optional[str] = None
    is_active: Optional[bool] = None


class SkillsListResponse(BaseModel):
    skills: List[AgentSkillRecord] = Field(default_factory=list)
    custom_skills: List[AgentSkillRecord] = Field(default_factory=list)
    builtin_skills_count: int = 6
    total_custom: int = 0


# ==============================================================================
# Agent Glass Pane, Continuous Evaluation & Feedback Schemas
# ==============================================================================

class FeedbackRating(str, Enum):
    THUMBS_UP = "THUMBS_UP"
    THUMBS_DOWN = "THUMBS_DOWN"
    NEEDS_REVISION = "NEEDS_REVISION"


class AttributedConstraintViolation(BaseModel):
    persona: Optional[str] = None
    file_path: Optional[str] = None
    violation: str = ""
    rule_or_directive: Optional[str] = None
    violation_message: Optional[str] = None
    severity: str = "WARNING"

    def __init__(self, **data: Any):
        if "violation" not in data and "violation_message" in data:
            data["violation"] = data["violation_message"]
        elif "violation_message" not in data and "violation" in data:
            data["violation_message"] = data["violation"]
        super().__init__(**data)


class AgentEvalMetric(BaseModel):
    instruction_adherence_score: float = Field(default=1.0, ge=0.0, le=1.0, description="Score 0.0-1.0 measuring negative constraint and directive compliance")
    grounding_score: float = Field(default=1.0, ge=0.0, le=1.0, description="Score 0.0-1.0 measuring validity of GCP APIs, resources, and modules")
    tool_efficiency_score: float = Field(default=1.0, ge=0.0, le=1.0, description="Score 0.0-1.0 measuring concise, efficient task completion")
    eval_judge_model: str = Field(default="gemini-3.7-flash", description="Model identifier used as the evaluation judge")
    eval_summary: str = Field(default="", description="Summary explanation of evaluation scores")
    constraint_violations: List[str] = Field(default_factory=list, description="Specific instructions or negative constraints violated")
    attributed_violations: List[AttributedConstraintViolation] = Field(default_factory=list, description="Constraint violations attributed to specific personas")
    evaluated_at: Optional[str] = None


class HumanFeedbackRecord(BaseModel):
    feedback_id: str = Field(description="Unique feedback UUID")
    trace_id: str
    stage_name: str
    rating: FeedbackRating = FeedbackRating.THUMBS_UP
    reviewer_email: str
    feedback_text: Optional[str] = None
    tags: List[str] = Field(default_factory=list, description="Categorization tags e.g. ['clean_hcl', 'missing_probes']")
    timestamp: str


class StageExecutionTraceRecord(BaseModel):
    trace_id: str
    stage_name: str
    rendered_prompt: str = Field(default="", description="Exact system prompt + skills + directives fed to agent")
    agent_output: str = Field(default="", description="Raw output generated by agent")
    created_at: str
    eval_metric: Optional[AgentEvalMetric] = None
    human_feedback: Optional[HumanFeedbackRecord] = None
    is_few_shot_candidate: bool = Field(default=False)


class SubmitFeedbackRequest(BaseModel):
    rating: FeedbackRating
    feedback_text: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class ApplyDirectiveRequest(BaseModel):
    directive: str = Field(description="Operational instruction rule to enforce on the agent (max 5 active per agent)")


class StreamlinePromptResponse(BaseModel):
    agent_role: str
    original_prompt: str
    streamlined_prompt: str
    directives_consolidated: List[str]
    diff_summary: str


class AgentHealthMetric(BaseModel):
    agent_role: str
    active_model: str
    average_adherence: float
    average_grounding: float
    approval_rate: float
    total_evals: int
    flakiest_directive: Optional[str] = None
    active_directives_count: int = 0


class GlassPaneOverviewResponse(BaseModel):
    platform_adherence_avg: float
    platform_grounding_avg: float
    total_reviews: int
    approval_rate_pct: float
    agents: List[AgentHealthMetric]


class AgentAttachedSkill(BaseModel):
    skill_id: str
    name: str
    description: str = ""
    trigger_keywords: List[str] = Field(default_factory=list)
    always_active: bool = False
    is_builtin: bool = True
    guidelines_snippet: str = ""


class AgentDetailsResponse(BaseModel):
    agent_id: str
    agent_role: str
    name: str
    role_title: str
    avatar_icon: str
    active_model: str
    base_prompt: str
    attached_skills: List[AgentAttachedSkill] = Field(default_factory=list)
    directives: List[str] = Field(default_factory=list)
    average_adherence: float = 1.0
    average_grounding: float = 1.0
    approval_rate: float = 100.0
    total_builds_evaluated: int = 0
    flakiest_directive: Optional[str] = None
    tooling: List[str] = Field(default_factory=list)
    selected_window: int = 10  # 5, 10, 25, 0 (all-time)
    adherence_trend: Optional[str] = None  # e.g. "+7% vs prior window", "Flat", "-5%"
    grounding_trend: Optional[str] = None   # e.g. "+2% vs prior window", "100% Stable"


class AgentEvaluationException(BaseModel):
    trace_id: str
    build_id: Optional[str] = None
    timestamp: str
    workload_id: Optional[str] = None
    category: str = "INSTRUCTION_OMISSION"  # INSTRUCTION_OMISSION, NEGATIVE_CONSTRAINT_VIOLATION, GCP_API_HALLUCINATION, TERRAFORM_SCHEMA_HALLUCINATION
    score: float = 0.0
    rule_or_directive: Optional[str] = None
    deduction_reason: str
    snippet_or_diff: Optional[str] = None


class AgentAuditExceptionsResponse(BaseModel):
    agent_id: str
    agent_role: str
    name: str
    avatar_icon: str
    average_adherence: float = 1.0
    average_grounding: float = 1.0
    total_builds_evaluated: int = 0
    flakiest_directive: Optional[str] = None
    hallucinations_detected_count: int = 0
    adherence_exceptions: List[AgentEvaluationException] = Field(default_factory=list)
    grounding_exceptions: List[AgentEvaluationException] = Field(default_factory=list)


# --- Re-export Prompt Registry Schemas ---
from shared.prompt_registry_schema import (
    AgentPromptDocument,
    PromptDiffResponse,
    PromptVersionRecord,
    PromptVersionSummary,
    PublishPromptRequest,
    RollbackPromptRequest,
)

# --- Re-export Dual-Architect Consensus Schemas ---
try:
    from shared.critic_schemas import (
        CritiqueCategory,
        CritiqueSeverity,
        CritiqueFinding,
        GauntletCheckResult,
        ArchitecturalCritique,
        ArchitectSubagentTelemetry,
        DualArchitectConsensusTelemetry,
    )
except ImportError:
    from critic_schemas import (
        CritiqueCategory,
        CritiqueSeverity,
        CritiqueFinding,
        GauntletCheckResult,
        ArchitecturalCritique,
        ArchitectSubagentTelemetry,
        DualArchitectConsensusTelemetry,
    )

try:
    from shared.qa_audit_schemas import (
        DeterministicGateReport,
        SecurityLensResult,
        AdherenceLensResult,
        CompositeAuditReport,
        ReleaseGateDecision,
    )
except ImportError:
    try:
        from qa_audit_schemas import (
            DeterministicGateReport,
            SecurityLensResult,
            AdherenceLensResult,
            CompositeAuditReport,
            ReleaseGateDecision,
        )
    except ImportError:
        pass


class DeployInfraRequest(BaseModel):
    branch: Optional[str] = "main"
    execution_mode: Optional[str] = "DEPLOY_ONLY"
    force: Optional[bool] = False


class DeployInfraResponse(BaseModel):
    status: str
    product_id: str
    execution_mode: str = "DEPLOY_ONLY"
    branch: str = "main"
    trace_id: str
    pubsub_message_id: Optional[str] = None
    execution: Optional[Dict[str, Any]] = None



# ==============================================================================
# Autonomous Mission Debrief & Self-Healing Ledger (AAR) Schemas
# ==============================================================================

class AAROutcomeType(str, Enum):
    SUCCESS_WITH_HEALING = "SUCCESS_WITH_HEALING"
    SUCCESS_CLEAN = "SUCCESS_CLEAN"
    FAILURE_RECOVERABLE = "FAILURE_RECOVERABLE"
    FAILURE_CRITICAL = "FAILURE_CRITICAL"


class SelfHealingIntervention(BaseModel):
    category: str = Field(description="Category: PACKAGING, GCP_APIS, NETWORKING_CIDR, RESOURCE_ADOPTION, SYNTAX_HEALING, CONSENSUS_AUDIT")
    component: str = Field(description="File, service, or API touched")
    issue_detected: str = Field(description="The underlying defect that would have caused deployment failure")
    autonomous_cure: str = Field(description="Action taken automatically to resolve without human intervention")


class RootCauseAnalysis(BaseModel):
    failing_component: Optional[str] = None
    failure_class: Optional[str] = None
    technical_explanation: Optional[str] = None


class BlastRadius(BaseModel):
    provisioned_resources: List[str] = Field(default_factory=list)
    failed_resource: Optional[str] = None
    blocked_resources: List[str] = Field(default_factory=list)


class RemediationPlan(BaseModel):
    recommended_mode: Optional[str] = None  # ARCHITECT_AND_DEV, DEPLOY_ONLY, RESUME_DEVELOPER, FULL, AUTO
    immediate_action: Optional[str] = None
    preventative_guidance: Optional[str] = None


class AfterActionReport(BaseModel):
    trace_id: str
    product_id: str
    status: str  # SUCCEEDED or FAILED
    outcome_type: AAROutcomeType
    executive_summary: str
    self_healing_interventions: List[SelfHealingIntervention] = Field(default_factory=list)
    root_cause: Optional[RootCauseAnalysis] = None
    blast_radius: Optional[BlastRadius] = None
    remediation: Optional[RemediationPlan] = None
    total_resources_provisioned: int = 0
    live_service_urls: List[str] = Field(default_factory=list)
    generated_at: str
    model_used: str
    # AAR-SETTINGS-MODEL: {code: AAR_MODEL_UNAVAILABLE | AAR_MODEL_CALL_FAILED, models: [{model, error}]} when no
    # model wrote the report (model_used is then "deterministic-rules"); None when a model wrote it
    model_failure: Optional[Dict[str, Any]] = None


class AARResponse(BaseModel):
    has_aar: bool
    aar: Optional[AfterActionReport] = None
    latest_trace_id: Optional[str] = None
    latest_status: Optional[str] = None


class WorkloadExecutionRun(BaseModel):
    trace_id: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    status: str
    feature_title: Optional[str] = None
    request_id: Optional[str] = None
    execution_mode: Optional[str] = None
    has_aar: bool = False
    outcome_type: Optional[str] = None
    healing_count: int = 0
