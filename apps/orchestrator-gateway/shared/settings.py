"""
Project Castor: Shared Platform Settings Client & Schemas
Provides centralized, validated configuration parameters across FinOps, Orchestration,
AI Models, and Platform Governance with thread-safe 60s in-memory caching and bounded audit logging.
"""

import copy
from enum import Enum
import logging
import os
import time
from typing import Any, Dict, List, Optional

try:
    from pydantic import BaseModel, Field, PrivateAttr, field_validator, model_validator
except ImportError:
    def PrivateAttr(default=None, default_factory=None, **_kwargs):  # no pydantic: a plain class attribute
        return default_factory() if default_factory is not None else default

    def field_validator(*_args, **_kwargs):  # no pydantic: no validation (the mock models below never validate)
        return lambda fn: fn

    def model_validator(*_args, **_kwargs):  # no pydantic: no validation (as field_validator above)
        return lambda fn: fn

    class MockFieldInfo:
        def __init__(self, default=None, default_factory=None):
            self.default = default
            self.default_factory = default_factory

        def get_value(self):
            if self.default_factory is not None:
                return self.default_factory()
            return self.default

    class MockBaseModel:
        def __init__(self, **kwargs):
            for cls in reversed(self.__class__.__mro__):
                for k, v in cls.__dict__.items():
                    if not k.startswith('_') and not callable(v):
                        default_val = v.get_value() if isinstance(v, MockFieldInfo) else v
                        if default_val is not Ellipsis:
                            setattr(self, k, default_val)
            for k, v in kwargs.items():
                curr = getattr(self, k, None)
                if isinstance(curr, MockBaseModel) and isinstance(v, dict):
                    setattr(self, k, curr.__class__(**v))
                elif isinstance(v, dict):
                    class AttrDict(dict):
                        def __getattr__(self, item):
                            val = self.get(item)
                            if isinstance(val, dict):
                                return AttrDict(val)
                            return val
                    setattr(self, k, AttrDict(v))
                else:
                    setattr(self, k, v)

        def model_dump(self):
            res = {}
            for k, v in self.__dict__.items():
                if not k.startswith('_'):
                    dump_fn = getattr(v, 'model_dump', None)
                    if callable(dump_fn):
                        res[k] = dump_fn()
                    elif isinstance(v, list):
                        res[k] = [
                            item.model_dump()
                            if callable(getattr(item, 'model_dump', None))
                            else item
                            for item in v
                        ]
                    elif isinstance(v, dict):
                        res[k] = {
                            ik: (
                                iv.model_dump()
                                if callable(getattr(iv, 'model_dump', None))
                                else iv
                            )
                            for ik, iv in v.items()
                        }
                    else:
                        res[k] = v
            return res

    def Field(default=None, default_factory=None, **kwargs):
        return MockFieldInfo(default=default, default_factory=default_factory)

    BaseModel = MockBaseModel

logger = logging.getLogger("castor-settings")

try:  # Argon compat (owner 10-14): the model-family table that model settings are validated against
    from shared.gemini_model_config import (DEFAULT_FALLBACK_MODELS, DEFAULT_PRIMARY_MODEL, DEFAULT_THINKING_LEVELS,
                                            UnsupportedModelConfig, known_model_id, validate_custom_families,
                                            validate_model_id, validate_model_ids, validate_thinking_levels)
except ImportError:  # pragma: no cover
    from .gemini_model_config import (DEFAULT_FALLBACK_MODELS, DEFAULT_PRIMARY_MODEL,  # type: ignore
                                      DEFAULT_THINKING_LEVELS, UnsupportedModelConfig, known_model_id,
                                      validate_custom_families, validate_model_id, validate_model_ids,
                                      validate_thinking_levels)


# ------------------------------------------------------------------------------
# FD-4AK: typed settings-read errors (fail closed)
# ------------------------------------------------------------------------------
class PlatformSettingsUnavailable(RuntimeError):
    """The stored platform settings could not be established. `get_platform_settings(strict=True)` raises a subclass;
    the default (lenient) read logs it and degrades instead. A missing document is NOT this error: a fresh install
    has no document and the compile-time defaults are then the real settings."""

    code = "PLATFORM_SETTINGS_UNAVAILABLE"

    def __init__(self, message: str, *, errors: Optional[List[Dict[str, Any]]] = None,
                 document: Optional[Dict[str, Any]] = None):
        super().__init__(f"{self.code}: {message}")
        self.message = message
        self.errors: List[Dict[str, Any]] = list(errors or [])
        # The stored document as read (PlatformSettingsInvalid only): lets an admin write path repair it while keeping
        # its audit history.
        self.document = document

    def again(self) -> "PlatformSettingsUnavailable":
        """A fresh instance of the same error (the negative cache re-raises it without growing one traceback)."""
        return type(self)(self.message, errors=self.errors, document=self.document)


class PlatformSettingsReadError(PlatformSettingsUnavailable):
    """Firestore (client, import or read) failed: the stored settings are unknown."""

    code = "PLATFORM_SETTINGS_READ_FAILED"


class PlatformSettingsInvalid(PlatformSettingsUnavailable):
    """The stored document exists but does not validate against PlatformSettings (or a write payload would not)."""

    code = "PLATFORM_SETTINGS_INVALID"


def settings_validation_errors(err: BaseException) -> List[Dict[str, Any]]:
    """Structured (model, loc, msg, type) entries for a validation failure; never the offending input value. `model`
    is the settings section model that failed (e.g. FinOpsSettings), since a section's loc starts inside it."""
    errs = err.errors() if callable(getattr(err, "errors", None)) else None
    model = str(getattr(err, "title", "") or "")
    if isinstance(errs, list):
        return [{"model": model, "loc": [str(p) for p in (e.get("loc") or ())], "msg": str(e.get("msg", "")),
                 "type": str(e.get("type", ""))} for e in errs if isinstance(e, dict)]
    return [{"model": model, "loc": [], "msg": str(err), "type": type(err).__name__}]


def _invalid_summary(err: BaseException, errors: List[Dict[str, Any]]) -> str:
    """The error type and the invalid field paths -- not str(err), which quotes the offending (stored) values."""
    locs = sorted({".".join(e["loc"]) or "<document>" for e in errors})
    return f"{type(err).__name__} in {locs}"


PLAN_APPROVAL_POLICIES = ("ON_COMPLIANCE_CONFLICT", "ALWAYS", "AUTONOMOUS_UNLESS_FAILED")


class BudgetBreachPolicy(str, Enum):
    AUTONOMOUS_SCALE_TO_ZERO = "AUTONOMOUS_SCALE_TO_ZERO"
    ALERT_ONLY = "ALERT_ONLY"
    HITL_CONFIRMATION_REQUIRED = "HITL_CONFIRMATION_REQUIRED"
    NUCLEAR_UNLINK_BILLING = "NUCLEAR_UNLINK_BILLING"


class FinOpsSettings(BaseModel):
    default_monthly_budget_usd: float = Field(
        default=40.0,
        ge=5.0,
        le=5000.0,
        description="FD-4CI-b: monthly budget ceiling (USD) of a NEW workload whose create form, API request or Drive "
                    "intake gives none (Control Center create; project vending for a record without a budget). "
                    "Existing workloads keep theirs.",
    )
    warning_threshold_pct: float = Field(
        default=80.0,
        ge=10.0,
        le=100.0,
        description="FD-4CI-b: when a Cloud Billing budget notification reports spend at or above this percentage "
                    "of a workload's ceiling (and below the circuit breaker), the Control Center records a "
                    "BUDGET_WARNING_THRESHOLD alert (billing_alerts, severity WARNING) and logs it. Nothing is "
                    "stopped. Unreadable settings: no warning is recorded.",
    )
    circuit_breaker_threshold_pct: float = Field(
        default=100.0,
        ge=50.0,
        le=200.0,
        description="FD-4CI-b: the workload's breach policy fires when spend reaches this percentage of its monthly "
                    "ceiling (100 = at the ceiling). An approved buffer ceiling is used as it is. Unreadable "
                    "settings: 100.",
    )
    enforce_scale_to_zero_default: bool = Field(
        default=True,
        description="FD-4CI-b: on (default), an Agent-mode Cloud Run service whose spec or architect plan states no "
                    "minimum instance count gets min_instances = 0 (scale to zero); off, it keeps 1 warm instance. A "
                    "stated minimum always wins. Read strictly per developer run; unreadable settings: 0.",
    )
    default_breach_policy: BudgetBreachPolicy = Field(
        default=BudgetBreachPolicy.AUTONOMOUS_SCALE_TO_ZERO,
        description="Default budget breach policy for newly vended workloads (AUTONOMOUS_SCALE_TO_ZERO, ALERT_ONLY, HITL_CONFIRMATION_REQUIRED, NUCLEAR_UNLINK_BILLING).",
    )


def terraform_version_accepted(version: Any) -> bool:
    """FD-4CI-b: True when the Terraform server's run-time check (mcp-servers/terraform/service.py `_ensure_binary`)
    accepts this Terraform version: below 1.6, the last MPL-2.0 series (1.6+ is refused, BSL). Same parse as that
    check (a leading "v" removed, the first two dot parts as integers, a non-numeric part counting as 0)."""
    if not isinstance(version, str) or not version.strip():
        return False
    parts = [int(p) if p.isdigit() else 0 for p in version.strip().lstrip("v").split(".")[:2]]
    major, minor = parts[0], (parts[1] if len(parts) > 1 else 0)
    return not (major > 1 or (major == 1 and minor >= 6))


class IaCEngineType(str, Enum):
    TERRAFORM = "TERRAFORM"
    OPENTOFU = "OPENTOFU"


# ------------------------------------------------------------------------------
# FD-7M-a (owner 10-31): approved deployable regions. A workload deploys into ONE region from the install's approved
# list, recorded once at creation on workloads/{product_id}.region; every consumer reads it through workload_region().
# ------------------------------------------------------------------------------
REGION_NOT_APPROVED = "REGION_NOT_APPROVED"


def is_region_id(value: Any) -> bool:
    """A Google Cloud region id: two or more dash-separated lowercase ASCII alphanumeric labels, at most 40 characters
    (e.g. us-central1, europe-west4). The same grammar as mcp-servers/gcloud/executor.py `is_region`. Grammar only:
    whether Google Cloud has the region is checked once, at the Settings save (Cloud Run's location list)."""
    if not isinstance(value, str) or len(value) > 40 or not value.isascii():
        return False
    parts = value.split("-")
    return len(parts) >= 2 and all(p and all(ch.islower() or ch.isdigit() for ch in p) for p in parts)


class RegionNotApproved(ValueError):
    """FD-7M-a: a workload region that is not in the install's approved deployable regions (a hand-edited record, or
    a create request naming another region). Typed: `code` / `error_class` REGION_NOT_APPROVED, the `stage` that
    refused, the `region` and the `approved` list. Never answered with another region."""

    code = REGION_NOT_APPROVED
    error_class = REGION_NOT_APPROVED

    def __init__(self, region: Any, approved: List[str], *, stage: str = "workload_region"):
        self.region = region
        self.approved = list(approved)
        self.stage = stage
        super().__init__(f"{REGION_NOT_APPROVED} at {stage}: region {region!r} is not in the approved deployable "
                         f"regions {self.approved} (Settings > Approved deployable regions)")


class OrchestrationSettings(BaseModel):
    default_gcp_region: str = Field(
        default="us-central1",
        description="Default Google Cloud region for infrastructure vending.",
    )
    approved_deployable_regions: List[str] = Field(
        default_factory=list,
        description="FD-7M-a: the regions a NEW workload may be created in (Settings, admin). Empty or missing = "
                    "[default_gcp_region] only, which is today's behavior. Each entry is a region id (letters, "
                    "digits and '-'), no entry twice, and default_gcp_region must be one of them. A workload keeps "
                    "the region recorded at its creation (workloads/{product_id}.region); a workload with no recorded "
                    "region follows default_gcp_region.",
    )
    default_iac_engine: IaCEngineType = Field(
        default=IaCEngineType.OPENTOFU,
        description="Default IaC execution engine for newly vended workloads (OPENTOFU or TERRAFORM).",
    )
    terraform_version: str = Field(
        default="1.5.7",
        description="Active platform HashiCorp Terraform release version (defaults to last MPL-2.0 release 1.5.7).",
    )
    tofu_version: str = Field(
        default="1.9.0",
        description="Active platform OpenTofu release version.",
    )
    supported_terraform_versions: List[str] = Field(
        default_factory=lambda: ["1.5.7"],
        description="FD-4CI-b: the Terraform versions offered in the Settings UI -- only versions the Terraform "
                    "server accepts at run time (below 1.6). A stored refused version is dropped when read.",
    )
    supported_tofu_versions: List[str] = Field(
        default_factory=lambda: ["1.8.8", "1.9.0", "1.10.0"],
        description="Curated list of available OpenTofu versions shown in Settings UI.",
    )
    default_terraform_timeout_seconds: int = Field(
        default=3600,
        ge=300,
        le=14400,
        description="Not used at present (stored only, not on the Settings page): no step reads it; the Cloud Build "
                    "timeout is runtimes.cloud_build_timeout_seconds.",
    )
    terraform_lock_timeout_seconds: int = Field(
        default=180,
        ge=10,
        le=600,
        description="FD-4CI-b: how long OpenTofu/Terraform waits for the workload's state lock (-lock-timeout on "
                    "plan/apply/destroy, and the Terraform server's pre-flight wait). The lock is never broken; when "
                    "it is still held the deploy stops with STATE_LOCKED. A TF_LOCK_TIMEOUT environment variable on "
                    "the Terraform server wins; unreadable settings: 180.",
    )
    stale_lock_threshold_minutes: int = Field(
        default=20,
        ge=5,
        le=120,
        description="FD-4CI-b: a held state lock older than this is reported as stale (lock_info.is_stale in the "
                    "STATE_LOCKED result). Report only: StackVend never clears a state lock automatically (FD-4H); "
                    "an operator uses force-unlock. TF_STALE_LOCK_MAX_AGE_MINUTES on the Terraform server wins; "
                    "unreadable settings: 20.",
    )
    max_pipeline_retries: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Not used at present (stored only, not on the Settings page): no step reads it.",
    )
    max_vending_timeout_seconds: int = Field(
        default=1200,
        ge=300,
        le=3600,
        description="Not used at present (stored only, not on the Settings page): no step reads it.",
    )
    default_branch: str = Field(
        default="main",
        description="FD-4CI-b-R1: the branch a NEW workload gets when its create request names none (Control "
                    "Center form / API target_branch, Drive intake): its repository is created with this default "
                    "branch (GitHub and Serverless Git), the generated deploy workflows trigger on it and release "
                    "pull requests target it. Existing workloads keep their recorded branch. A value that is not a "
                    "plain branch name (letters, digits, '.', '_', '-', '/') is not applied: main is used (logged); "
                    "unreadable settings: main. FD-4CI-b-R1-WIF: the workload's GitHub identity-federation condition "
                    "accepts its recorded branch (only that one), so GitHub Actions deploys from it work; a workload "
                    "created before that change keeps main there until its next pipeline run regenerates its IaC.",
    )
    default_folder_id: str = Field(
        default="",
        description="Not used at present (stored only, not on the Settings page): the default folder for new "
                    "workloads is chosen on the GCP Folders tab.",
    )
    ipam_supernet_cidr: str = Field(
        default="10.100.0.0/16",
        description="Platform supernet pool that every workload network range is taken from: workload subnets, "
                    "Serverless VPC Access Connector ranges and Private Services Access ranges.",
    )
    ipam_connector_prefix: int = Field(
        default=28,
        ge=26,
        le=29,
        description="Subnet prefix length for Serverless VPC Access Connectors (Google Cloud requires /28).",
    )
    ipam_subnet_prefix: int = Field(
        default=24,
        ge=20,
        le=28,
        description="Subnet prefix length for standard workload subnets (Cloud SQL, Redis, VMs).",
    )
    # TI-5-R2 P1 (owner 10-25, FOLLOWUPS-1025): the size of the Private Services Access range the platform allocates
    # from the pool for a typed workload's private network (AlloyDB, Cloud SQL, Vertex AI endpoint peering). Read by
    # developer_agent/platform_facts.load_ipam_pool, the one IPAM pool reader of the architect and developer stages.
    # Applies to new allocations only: a workload's existing range is reused as it is.
    ipam_psa_prefix: int = Field(
        default=20,
        ge=16,
        le=24,
        description="Prefix length of each workload's Private Services Access range (typed infrastructure: "
                    "AlloyDB, Cloud SQL, Vertex AI endpoints). Google Cloud needs an allocated range of at least "
                    "/24; AlloyDB and Cloud SQL each use a /24 of it, so the default /20 holds 16 of them, and a larger "
                    "range (a /16 is a common choice) leaves more room. Each range must fit in the supernet pool.",
    )
    default_container_memory_mb: int = Field(
        default=512,
        ge=128,
        le=32768,
        description="FD-4CI-b: memory (MB) of an Agent-mode Cloud Run service with no heavy packages; a data or "
                    "compute sizing tier keeps its larger value. Read strictly per developer run; a value Cloud Run "
                    "cannot run with the vCPU below, or unreadable settings: 512.",
    )
    default_container_cpu: int = Field(
        default=1,
        ge=1,
        le=8,
        description="FD-4CI-b: vCPU of an Agent-mode Cloud Run service with no heavy packages (1, 2, 4, 6 or 8); a "
                    "compute sizing tier keeps its larger value. Unreadable settings or an invalid combination: 1.",
    )
    # BUILD-ADMISSION-QUEUE (G4, owner 11-13): read by shared/build_admission.py (Control Center and gateway intake).
    max_concurrent_builds: int = Field(
        default=1,
        ge=1,
        le=20,
        description="How many LLM-heavy pipeline runs (new Agent-mode workloads, Full and Resume Developer relaunches, "
                    "promotions, Drive / refactor / SRE builds) may run at the same time. Over the limit a run waits "
                    "in a first-in-first-out queue (status QUEUED; it can be cancelled) and starts when a running "
                    "build ends. Fast-Path Deploy, Express, redeploy and IaC upgrades never wait. Lowering it never "
                    "stops a running build. Unreadable settings: 1.",
    )
    high_memory_container_mb: int = Field(
        default=1024,
        ge=256,
        le=32768,
        description="Not used at present (stored only, not on the Settings page): no step reads it.",
    )
    high_cpu_container: int = Field(
        default=2,
        ge=1,
        le=8,
        description="Not used at present (stored only, not on the Settings page): no step reads it.",
    )

    @field_validator("supported_terraform_versions")
    @classmethod
    def _runtime_accepted_terraform_versions(cls, v):
        # FD-4CI-b: offer only versions the Terraform server accepts (a stored 1.7.5 / 1.8.5 / 1.9.0 is dropped)
        if not isinstance(v, list):
            return v
        return [x for x in v if terraform_version_accepted(x)] or ["1.5.7"]

    @field_validator("approved_deployable_regions")
    @classmethod
    def _approved_regions_grammar(cls, v):
        # FD-7M-a: validated, never rewritten (an invalid entry makes the document invalid; nothing is dropped)
        if not isinstance(v, list):
            return v
        bad = [i for i, r in enumerate(v) if not is_region_id(r)]
        if bad:
            raise ValueError(f"approved_deployable_regions entries {bad} are not region ids (e.g. us-central1)")
        if len(set(v)) != len(v):
            raise ValueError("approved_deployable_regions names a region more than once")
        return v

    @model_validator(mode="after")
    def _default_region_is_approved(self):
        regions = getattr(self, "approved_deployable_regions", None)
        if isinstance(regions, list) and regions and self.default_gcp_region not in regions:
            raise ValueError("default_gcp_region must be one of approved_deployable_regions")
        return self


def approved_deployable_regions(orchestration: Any) -> List[str]:
    """FD-7M-a: the effective approved list of `orchestration` (an OrchestrationSettings, or the stored
    `orchestration` mapping, validated here): the stored list, or [default_gcp_region] when it is empty or missing."""
    orch = _orchestration_model(orchestration)
    regions = list(orch.approved_deployable_regions or [])
    return regions or [orch.default_gcp_region]


def _orchestration_model(orchestration: Any) -> "OrchestrationSettings":
    if isinstance(orchestration, OrchestrationSettings):
        return orchestration
    if isinstance(orchestration, dict):
        return OrchestrationSettings(**orchestration)
    raise TypeError(f"orchestration settings must be OrchestrationSettings or a mapping, got "
                    f"{type(orchestration).__name__}")


def workload_region(record_region: Any, orchestration: Any, *, default_region: Optional[str] = None,
                    stage: str = "workload_region") -> str:
    """FD-7M-a: the region a workload deploys into.

    `record_region` is workloads/{product_id}.region as read (None when the record has no such field: a workload
    created before FD-7M-a). `orchestration` is the install's orchestration settings (OrchestrationSettings, or the
    stored mapping). `default_region` is the caller's already-resolved platform region (FD-4AL: the setting, then
    $REGION / $DEFAULT_REGION); None = orchestration.default_gcp_region.

    * no record region (None) -> the default region (today's behavior, unchanged);
    * a record region in the approved list -> that region;
    * anything else (not approved, not a string, blank) -> RegionNotApproved (REGION_NOT_APPROVED), never another
      region."""
    orch = _orchestration_model(orchestration)
    if record_region is None:
        return default_region if default_region is not None else orch.default_gcp_region
    approved = approved_deployable_regions(orch)
    if isinstance(record_region, str) and record_region in approved:
        return record_region
    raise RegionNotApproved(record_region, approved, stage=stage)


class ModelDefaultReason(str, Enum):
    """DEFAULT-MODEL-GEMINI-4-CARBON RT F2: why a model field holds its code default although no administrator chose
    it. Such a field does not lead a cascade with the code default (gemini-4-carbon): the GEMINI_MODEL env, the model
    the services ran before this change, leads instead (logged at WARNING)."""
    SETTINGS_UNAVAILABLE = "PLATFORM_SETTINGS_UNAVAILABLE"   # read failure, no last good copy: every model field
    UNSUPPORTED_STORED_MODEL = "UNSUPPORTED_MODEL_CONFIG"    # the stored id had no request rules: that field reset


class AgentModelSettings(BaseModel):
    # RT F2: {model field: ModelDefaultReason} for the fields that hold their code default because the settings were
    # not read as stored (set by get_platform_settings / platform_settings_from_stored only; never stored or dumped).
    _model_default_reasons: Dict[str, Any] = PrivateAttr(default_factory=dict)
    # OPEN-MODEL-SETTINGS (owner 11-10). Declared FIRST: the model-id validators below read it (pydantic validates the
    # fields in declaration order and hands them the earlier values). The Control Center writes it from the live check
    # of a save (PUT /api/settings); a value sent by a client is replaced by the server's.
    custom_families: Dict[str, str] = Field(
        default_factory=dict,
        description="OPEN-MODEL-SETTINGS: the request style (LEVEL = Gemini 4 rules, BUDGET = Gemini 3.x rules) of "
                    "each model id in use that has no built-in rules, keyed by the lower-case id. Written by the "
                    "Control Center's live check when the model is saved; built-in ids never need an entry.",
    )
    # THINKING-LEVEL-SETTINGS (owner 11-10)
    thinking_levels: Dict[str, str] = Field(
        default_factory=lambda: dict(DEFAULT_THINKING_LEVELS),
        description="THINKING-LEVEL-SETTINGS: thinking level (LOW, MEDIUM or HIGH; MINIMAL is refused) per role "
                    "(architect, developer, repair, auxiliary = QA judges, compliance, assistant, FinOps advisor) "
                    "for Gemini 4 thinking-level models (Argon, Carbon, and any custom model stored with the LEVEL "
                    "style). "
                    "Gemini 3.x models use the thinking budget instead. Default architect LOW, developer MEDIUM, "
                    "repair LOW, auxiliary LOW; a role left out takes its default.",
    )
    # DEFAULT-MODEL-GEMINI-4-CARBON (owner 11-11): every role defaults to DEFAULT_PRIMARY_MODEL (gemini-4-carbon) and
    # the fallback list to DEFAULT_FALLBACK_MODELS (DEFAULT-FALLBACK-CHAIN 11-13: gemini-4-argon, gemini-3.8-flash,
    # gemini-3.7-flash). A stored value is used as it is.
    architect_model: str = Field(
        default=DEFAULT_PRIMARY_MODEL,
        description="Plan 13: Gemini model for specification decomposition and DAG generation.",
    )
    developer_model: str = Field(
        default=DEFAULT_PRIMARY_MODEL,
        description="Gemini model for application synthesis and test creation.",
    )
    finops_model: str = Field(
        default=DEFAULT_PRIMARY_MODEL,
        description="FD-4CI-b-R2: the model that writes a short recommendation on each budget-breach approval "
                    "card (one call per card, made after the enforcement action and never delaying it; 20 s timeout, "
                    "256 answer tokens). It sees only the workload id and the spend numbers (spend, ceiling, percent "
                    "of the ceiling); its text is shown as plain text. A failed call leaves the card without a recommendation and with a "
                    "typed note. Tokens and cost are recorded on the card. The cost check before a build is still "
                    "the deterministic Infracost estimate and enforcement still follows the breach policy.",
    )
    assistant_model: str = Field(
        default=DEFAULT_PRIMARY_MODEL,
        description="Gemini model backing the conversational Control Center assistant.",
    )
    repair_model: str = Field(
        default="",
        description="Gemini model for hallucination-stack repair calls; empty = the developer model (owner D1). "
                    "Argon compat (owner 10-14): lets repair run on another model than the developer's.",
    )
    max_output_tokens: int = Field(
        default=65536,
        ge=1024,
        le=65536,
        description="FD-4CI-b: global output-token limit (default 65,536): the developer's limit when its override "
                    "is empty and the architect's when its override is empty. Stored values are used as they are "
                    "(no longer raised).",
    )
    architect_max_output_tokens: Optional[int] = Field(
        default=16384,
        ge=1024,
        le=65536,
        description="Architect and red-team critic output-token limit (default 16,384); empty (None) = the global "
                    "max_output_tokens.",
    )
    developer_max_output_tokens: Optional[int] = Field(
        default=65536,
        ge=1024,
        le=65536,
        description="Developer output-token limit (default 65,536); empty (None) = the global max_output_tokens.",
    )

    def get_architect_token_limit(self) -> int:
        # FD-4CI-b: a cleared override inherits the global limit (it used to mean 16,384)
        return self.architect_max_output_tokens or self.max_output_tokens or 16384

    def get_developer_token_limit(self) -> int:
        return self.developer_max_output_tokens or self.max_output_tokens or 65536

    default_thinking_budget: int = Field(
        default=0,
        ge=0,
        le=2048,
        description="FD-4CI-b: thinking budget (tokens) sent with the architect's plan call and the developer's calls "
                    "(lead decomposition, swarm juniors, single-call generation) on budget-family models (Gemini "
                    "3.x and earlier); 0 = no thinking config is sent (the model's own default, as before). "
                    "Gemini 4 thinking-level models (Argon, Carbon, and any custom model stored with the LEVEL "
                    "style) use their role's thinking level (thinking_levels) instead; the typed-IaC junior call and "
                    "repair calls keep their own budgets; the critic, decomposer and compliance calls send none.",
    )
    max_swarm_token_envelope: int = Field(
        default=350_000,
        ge=50_000,
        le=2_000_000,
        description="FinOps circuit breaker ceiling for Developer Swarm total input+output tokens per build.",
    )
    fallback_models: List[str] = Field(
        default_factory=lambda: list(DEFAULT_FALLBACK_MODELS),
        description="Dynamic fallback models to cascade through when primary model is rate-limited or unavailable. "
                    "OPEN-MODEL-SETTINGS RT F2: a save may list at most 4 (each new entry is one live call); the "
                    "limit is checked where the settings are saved (Control Center), not on load, so a longer "
                    "stored list never makes the settings unreadable.",
    )
    custom_directives: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Admin-managed operational directives per agent role (max 5 per agent).",
    )

    # Argon compat (owner 10-14): an unknown model id is refused here -- at settings save (CC PUT /api/settings ->
    # 422 UNSUPPORTED_MODEL_CONFIG) and load -- never at a live model call. "" = the default. OPEN-MODEL-SETTINGS:
    # an id with a request style in this document's custom_families is accepted like a built-in one.
    @field_validator("custom_families", mode="before")
    @classmethod
    def _custom_families(cls, v):
        return validate_custom_families({} if v is None else v)

    @field_validator("thinking_levels", mode="before")
    @classmethod
    def _thinking_levels(cls, v):
        return validate_thinking_levels(v)

    @field_validator("architect_model", "developer_model", "finops_model", "assistant_model", "repair_model")
    @classmethod
    def _known_model_id(cls, v, info):
        return validate_model_id(v, info.field_name, (info.data or {}).get("custom_families") or {})

    @field_validator("fallback_models")
    @classmethod
    def _known_fallback_ids(cls, v, info):
        return validate_model_ids(v, "fallback_models", (info.data or {}).get("custom_families") or {})


class GovernanceSettings(BaseModel):
    # settings-toggles (FD-4AK Fable RT F5): the readers are maintenance_refusal / new_run_refusal,
    # compliance_advisories_block and destructive_tf_requires_approval below.
    maintenance_mode: bool = Field(
        default=False,
        description="When enabled, no new run starts (Control Center create/retrigger/deploy, Docs intake, gateway "
                    "dispatch answer 503 MAINTENANCE_MODE). Runs already in flight continue; admin operations work.",
    )
    strict_compliance_gates: bool = Field(
        default=True,
        description="Compliance gates always run. When enabled, a compliance profile advisory makes the pre-build "
                    "gate wait for human approval (not under plan_approval_policy AUTONOMOUS_UNLESS_FAILED).",
    )
    require_hitl_for_destructive_tf: bool = Field(
        default=True,
        description="When enabled, an Agent deploy whose Terraform plan deletes or replaces a data-holding resource "
                    "stops before the apply (DESTROY_REQUIRES_APPROVAL) for an operator decision.",
    )
    drive_folder_auto_discovery: bool = Field(
        default=False,
        description="OSS-D18 (owner 10-19): when enabled, the Docs intake poller also discovers every Drive "
                    "'01_Inbox_Requests' folder shared with the platform service account (zero-config). Off by "
                    "default: only the explicitly configured inbox / in-progress folders (INBOX_FOLDER_ID / "
                    "IN_PROGRESS_FOLDER_ID or the poll request) are polled. FD-4AS: when on, a discovered inbox is "
                    "polled only if its Drive owner is an authorized submitter (active Control Center user, role "
                    "ADMIN, WORKLOAD_MANAGER or legacy APPROVER), and every document must be owned by one, on or "
                    "off.",
    )
    iac_intent_generate: bool = Field(
        default=True,
        description="TI-3h (owner 10-21): typed infrastructure (generate mode). When enabled, a NEW workload with a "
                    "typed service topology declares its infrastructure as a typed intent that the platform renders "
                    "(the developer gateway's generate mode). Existing workloads keep their path (a "
                    "workload with an intent stays on it, a legacy workload stays legacy). Cloud SQL, Redis, AlloyDB, "
                    "Vertex AI endpoints and Bigtable are built on the typed path (the platform supplies the "
                    "private network, its IPAM Private Services Access range and the Cloud Run VPC connector "
                    "where needed; TI-5c, TI-5-R2, TI-5-F4). Turning it off affects new workloads only. "
                    "GEN-DEFAULT (owner 10-26): on by default. The default applies only where the stored settings "
                    "document has no value (no document, no governance section, or no such key); an explicitly "
                    "stored value, on or off, is kept. Read strictly per developer run: unreadable or invalid "
                    "settings keep it off.",
    )
    freeze_new_workloads: bool = Field(
        default=True,
        description="FD-4CU (owner 10-21): when enabled, every NEW workload (Control Center create, promote, project "
                    "vending of a workload with no code_freeze value yet) starts with code_freeze on, so automatic "
                    "runs (SRE auto-healing, code scanner pull requests, Upgrade IaC) wait until an operator "
                    "unfreezes it. The first spec build and deploy still run. Existing workloads are never changed. "
                    "Read strictly at creation: missing or unreadable settings start the workload frozen.",
    )
    vcs_provider: Optional[str] = Field(
        default_factory=lambda: os.getenv("VCS_PROVIDER", "GITHUB"),
        description="Platform default VCS provider: 'GITHUB' or 'SERVERLESS_GIT' (defaults to VCS_PROVIDER env or GITHUB).",
    )
    git_server_url: Optional[str] = Field(
        default=None,
        description="Serverless Git microservice endpoint URL.",
    )
    default_require_human_code_review: bool = Field(
        default=True,
        description="Default HITL code review requirement for all new workloads (Auto-Merge: False).",
    )
    require_plan_approval: bool = Field(
        default=False,
        description="Requires human architect review and approval of the architectural implementation plan before Developer Agent code generation.",
    )
    plan_approval_policy: str = Field(
        default="ON_COMPLIANCE_CONFLICT",
        description="Trigger policy for architectural plan HITL gate: 'ALWAYS', 'ON_COMPLIANCE_CONFLICT', or 'AUTONOMOUS_UNLESS_FAILED'.",
    )

    # FD-4AK: an unknown policy was silently treated as "no approval unless conflicts". The compliance gate always
    # upper-cased the value, so the stored spelling is normalized the same way; anything else is refused (PUT 422,
    # stored document invalid).
    @field_validator("plan_approval_policy", mode="before")
    @classmethod
    def _known_plan_approval_policy(cls, v):
        if not isinstance(v, str):
            return v   # the str type check reports it
        policy = v.strip().upper()
        if policy not in PLAN_APPROVAL_POLICIES:
            raise ValueError(f"plan_approval_policy must be one of {list(PLAN_APPROVAL_POLICIES)}")
        return policy


class RuntimeSettings(BaseModel):
    default_python_version: str = Field(
        default="3.13",
        description="Default Python runtime enforced across Buildpack compilations.",
    )
    cloud_build_machine_type: str = Field(
        default="E2_HIGHCPU_8",
        description="Worker machine type for Cloud Build execution (E2_HIGHCPU_8, E2_STANDARD_2, etc.).",
    )
    cloud_build_timeout_seconds: int = Field(
        default=1200,
        description="Maximum polling timeout in seconds for buildpack container compilation.",
    )
    auto_harmonize_wheels: bool = Field(
        default=True,
        description="FD-4DJ-HARMONIZE: on (default), a container image build relaxes old numpy / scipy / pandas / "
                    "asyncpg pins in the build's copy of requirements.txt to ranges with Python 3.13 wheels, unless "
                    "package_versions (Centrally Governed Package Versions) lists the package: then its bound is "
                    "used (by default all four are listed, so turning the switch off changes nothing until a package "
                    "is removed from that list). Off: those old pins are kept as written; the package_versions "
                    "bounds and the starlette / greenlet lines still apply. The Terraform server reads it at build "
                    "time; unreadable settings: on.",
    )
    artifact_registry_virtual_repo: Optional[str] = Field(
        default=None,
        description="Not used at present (stored only, not on the Settings page): no step reads it.",
    )
    package_versions: Dict[str, str] = Field(
        default_factory=lambda: {
            "numpy": ">=1.26.0",
            "pandas": ">=2.2.0",
            "scipy": ">=1.14.0",
            "fastapi": ">=0.110.0",
            "starlette": ">=0.37.2,<1.0.0",
            "uvicorn": ">=0.28.0",
            "google-cloud-firestore": ">=2.15.0",
            "pydantic": ">=2.6.0",
            "asyncpg": ">=0.30.0,<1.0.0",
            "greenlet": ">=3.1.1,<4.0.0",
            "sqlalchemy": ">=2.0.36,<3.0.0",
            "psycopg": ">=3.2.0,<4.0.0",
            "psycopg2-binary": ">=2.9.10,<3.0.0",
            "cryptography": ">=43.0.0,<45.0.0",
            "email-validator": ">=2.0.0,<3.0.0",
        },
        description="Centrally governed Bill of Materials (BOM) package versions and constraints.",
    )


# The retired fallback ids the purge removes, compared exactly through the model-id rule (OPEN-MODEL-SETTINGS RT F1:
# the old substring test `"2.5" in m or "3.8-pro" in m` also dropped legal custom ids such as `acme-2.5-turbo`).
PURGED_LEGACY_FALLBACK_IDS = frozenset({"gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.5-pro",
                                        "gemini-3.8-pro"})


def _purge_legacy_fallbacks(models: List[str]) -> List[str]:
    """The fallback list without the retired ids (exact ids, `<id>-<suffix>` builds and path prefixes included); the
    default fallback when nothing is left."""
    return ([m for m in models if known_model_id(m) not in PURGED_LEGACY_FALLBACK_IDS]
            or list(DEFAULT_FALLBACK_MODELS))


def _is_model_id_list(v: Any) -> bool:
    """FD-4AK RT R3: the fallback purge only filters a list of str; anything else is left for pydantic."""
    return isinstance(v, list) and all(isinstance(m, str) for m in v)


class SettingsAuditEntry(BaseModel):
    timestamp: str = Field(description="ISO 8601 UTC timestamp")
    admin_email: str = Field(description="Admin user email")
    action: str = Field(default="UPDATE_SETTINGS", description="Action taken")
    changed_fields: Dict[str, Any] = Field(default_factory=dict, description="Fields changed")


class PlatformSettings(BaseModel):
    finops: FinOpsSettings = Field(default_factory=FinOpsSettings)
    orchestration: OrchestrationSettings = Field(default_factory=OrchestrationSettings)
    models: AgentModelSettings = Field(default_factory=AgentModelSettings)
    governance: GovernanceSettings = Field(default_factory=GovernanceSettings)
    runtimes: RuntimeSettings = Field(default_factory=RuntimeSettings)
    audit_log: List[SettingsAuditEntry] = Field(
        default_factory=list, description="Bounded circular buffer of last 15 update records"
    )
    updated_at: Optional[str] = None
    updated_by: Optional[str] = None
    version: int = Field(default=1, description="Config Version: +1 on every save. FD-4CI-b: a PUT /api/settings whose "
                                                "version is not the stored one is refused (409 SETTINGS_VERSION_CONFLICT).")

    @property
    def vcs_provider(self) -> Optional[str]:
        return self.governance.vcs_provider or os.getenv("VCS_PROVIDER") or "GITHUB"

    @vcs_provider.setter
    def vcs_provider(self, value: Optional[str]):
        self.governance.vcs_provider = str(value).strip().upper() if value else None

    @property
    def git_server_url(self) -> str:
        return self.governance.git_server_url

    @git_server_url.setter
    def git_server_url(self, value: str):
        self.governance.git_server_url = str(value).strip().rstrip("/") if value else ""

    def __init__(self, **kwargs):
        # FD-4AK: a section that is present but not a mapping (e.g. `governance: "x"` or `null`) used to become that
        # section's defaults silently -- one bad value (stored, or in a PUT body: pydantic runs this __init__ for
        # model_validate too) reset every governance gate. Only an ABSENT section takes the defaults now; any other
        # value stays in kwargs, so the pydantic validation below refuses it like any other invalid field.
        def _take(name, model_cls, accepted=(dict,)):
            if name in kwargs and isinstance(kwargs[name], accepted + ((model_cls,) if model_cls else ())):
                return kwargs.pop(name)
            return None

        finops_val = _take("finops", FinOpsSettings)
        orch_val = _take("orchestration", OrchestrationSettings)
        models_val = _take("models", AgentModelSettings)
        gov_val = _take("governance", GovernanceSettings)
        # RT R3: only a list of mappings / entries is pre-built below; any other list stays for pydantic (real loc)
        audit_val = (_take("audit_log", None, accepted=(list,))
                     if isinstance(kwargs.get("audit_log"), list)
                     and all(isinstance(x, (dict, SettingsAuditEntry)) for x in kwargs["audit_log"]) else None)

        super().__init__(**kwargs)

        if isinstance(finops_val, FinOpsSettings):
            self.finops = FinOpsSettings(**finops_val.model_dump())
        elif isinstance(finops_val, dict):
            self.finops = FinOpsSettings(**finops_val)
        else:
            self.finops = FinOpsSettings()

        if isinstance(orch_val, OrchestrationSettings):
            self.orchestration = OrchestrationSettings(**orch_val.model_dump())
        elif isinstance(orch_val, dict):
            self.orchestration = OrchestrationSettings(**orch_val)
        else:
            self.orchestration = OrchestrationSettings()

        if isinstance(models_val, AgentModelSettings):
            dump = models_val.model_dump()
            if dump.get("fallback_models") and _is_model_id_list(dump.get("fallback_models")):
                dump["fallback_models"] = _purge_legacy_fallbacks(dump["fallback_models"])
            self.models = AgentModelSettings(**dump)
        elif isinstance(models_val, dict):
            models_val = dict(models_val)
            if models_val.get("fallback_models") and _is_model_id_list(models_val.get("fallback_models")):
                models_val["fallback_models"] = _purge_legacy_fallbacks(models_val["fallback_models"])
            self.models = AgentModelSettings(**models_val)
        else:
            self.models = AgentModelSettings()

        if isinstance(gov_val, GovernanceSettings):
            self.governance = GovernanceSettings(**gov_val.model_dump())
        elif isinstance(gov_val, dict):
            self.governance = GovernanceSettings(**gov_val)
        else:
            self.governance = GovernanceSettings()

        if isinstance(audit_val, list):
            self.audit_log = [
                x if isinstance(x, SettingsAuditEntry) else SettingsAuditEntry(**x)
                for x in audit_val
            ]
        else:
            self.audit_log = []


# ------------------------------------------------------------------------------
# In-Memory Cache & Client
# ------------------------------------------------------------------------------
_SETTINGS_CACHE: Optional[PlatformSettings] = None   # only ever a GOOD value: the stored doc, or defaults (no doc)
_LAST_FETCH_TIME: float = 0.0
_CACHE_TTL_SECONDS: float = 60.0
# FD-4AK negative cache: the last failed read, so a Firestore outage is not re-read on every call.
_LAST_FAILURE: Optional[PlatformSettingsUnavailable] = None
_LAST_FAILURE_TIME: float = 0.0
# FD-4AK RT R2: a failure is remembered only briefly -- strict callers fail closed, so a 1 s Firestore blip must not be
# a 60 s refusal. force_refresh always bypasses it.
_NEGATIVE_CACHE_TTL_SECONDS: float = 5.0


_MODEL_ID_FIELDS = ("architect_model", "developer_model", "finops_model", "assistant_model", "repair_model",
                    "fallback_models")


def _unsupported_model_fields(err: Exception) -> List[str]:
    """The model-id fields an UNSUPPORTED_MODEL_CONFIG validation error names (empty: some other error)."""
    errs = err.errors() if callable(getattr(err, "errors", None)) else []
    out: List[str] = []
    for er in errs:
        field = next((p for p in reversed(tuple(er.get("loc") or ())) if p in _MODEL_ID_FIELDS), None)
        if isinstance((er.get("ctx") or {}).get("error"), UnsupportedModelConfig) and field:
            out.append(field)
        else:
            return []
    return sorted(set(out))


ROLE_MODEL_FIELDS = ("architect_model", "developer_model", "finops_model", "assistant_model", "repair_model")


def _mark_model_defaults(models: Any, fields: Any, reason: "ModelDefaultReason") -> None:
    """Record (RT F2) that `fields` of `models` hold their code default for `reason`."""
    current = getattr(models, "_model_default_reasons", None)
    merged = {**(current if isinstance(current, dict) else {}), **{f: reason for f in fields}}
    try:
        models._model_default_reasons = merged
    except Exception as e:  # noqa: BLE001 - a settings object that cannot carry the record: say so, never guess
        logger.error(f"model default reasons not recorded ({type(e).__name__}: {e}): {sorted(merged)}")


def model_default_reason(models: Any, field: str) -> Optional["ModelDefaultReason"]:
    """The ModelDefaultReason of `field` in an AgentModelSettings-like object, or None (a stored or chosen value, or
    the defaults of an install that has no settings document yet)."""
    reasons = getattr(models, "_model_default_reasons", None)
    reason = reasons.get(field) if isinstance(reasons, dict) else None
    return reason if isinstance(reason, ModelDefaultReason) else None


def platform_settings_from_stored(data: Dict[str, Any]) -> "PlatformSettings":
    """PlatformSettings from the STORED document (Argon RT F1): strict at save (PUT /api/settings -> 422), lenient
    here. An unknown model id resets only that model field to its default (ERROR logged with the code); every other
    stored setting (FinOps, governance, orchestration, the other model fields) still applies. Any other validation
    error is raised as before. A document with only known ids is parsed exactly as before."""
    try:
        return PlatformSettings(**data)
    except Exception as v_err:
        bad = _unsupported_model_fields(v_err)
        if not bad or not isinstance(data.get("models"), dict):
            raise
        defaults = AgentModelSettings()
        models = dict(data["models"])
        for field in bad:
            models[field] = getattr(defaults, field)
        logger.error(f"UNSUPPORTED_MODEL_CONFIG: stored platform settings name a model id with no request rules in "
                     f"{bad}; those fields fall back to their defaults, the rest of the stored settings apply "
                     f"({v_err})")
        result = PlatformSettings(**{**data, "models": models})
        _mark_model_defaults(result.models, [f for f in bad if f in ROLE_MODEL_FIELDS],
                             ModelDefaultReason.UNSUPPORTED_STORED_MODEL)
        return result


def validate_settings_document(data: Any) -> PlatformSettings:
    """FD-4AK write-side check: the WHOLE document, exactly as it would be stored, against PlatformSettings. Strict:
    no field is reset to a default (the read side's unknown-model-id leniency does not apply). Raises
    PlatformSettingsInvalid with structured errors; returns the parsed settings on success."""
    if not isinstance(data, dict):
        raise PlatformSettingsInvalid(f"the settings document must be a mapping, got {type(data).__name__}",
                                      errors=[{"loc": [], "msg": "not a mapping", "type": type(data).__name__}])
    try:
        return PlatformSettings(**data)
    except Exception as e:  # noqa: BLE001 - every construction failure is an invalid document
        errors = settings_validation_errors(e)
        raise PlatformSettingsInvalid(f"settings document does not validate: {_invalid_summary(e, errors)}",
                                      errors=errors) from e


def _read_stored_document(project_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """One read of system_config/platform_settings: the stored mapping, or None when there is no document (a fresh
    install: the defaults ARE the settings). Raises PlatformSettingsReadError (Firestore unusable) or
    PlatformSettingsInvalid (not a mapping) -- never substitutes defaults for a document it could not read."""
    try:
        from google.cloud import firestore

        pid = project_id or os.getenv("PROJECT_ID")
        db = firestore.Client(project=pid) if pid else firestore.Client()
        doc = db.collection("system_config").document("platform_settings").get()
        exists = bool(doc.exists)
        data = doc.to_dict() if exists else None
    except Exception as e:  # noqa: BLE001 - client, import, auth and read failures all mean "settings unknown"
        raise PlatformSettingsReadError(f"could not read system_config/platform_settings: {type(e).__name__}: {e}") from e
    if not exists:
        return None
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise PlatformSettingsInvalid(f"system_config/platform_settings is not a mapping ({type(data).__name__})",
                                      errors=[{"loc": [], "msg": "not a mapping", "type": type(data).__name__}])
    return data


def get_platform_settings(
    force_refresh: bool = False, project_id: Optional[str] = None, strict: bool = False
) -> PlatformSettings:
    """
    Retrieves the singleton PlatformSettings document with 60-second in-memory caching.

    FD-4AK: a missing document (fresh install) gives the compile-time defaults. A failed read or an invalid
    document is a PlatformSettingsUnavailable:
      * strict=True (governance gates, approval / HITL defaults, FinOps intake defaults, IPAM pool, region): raised
        to the caller, which must fail closed. It is never replaced by defaults or a stale value.
      * strict=False (display, model choice, token limits, tool versions): logged at ERROR; the last good value read
        by this process is returned, else the defaults (which are NOT cached as if they had been read).
    A failure is remembered for _NEGATIVE_CACHE_TTL_SECONDS (5 s), so an outage is retried every few seconds, not on
    every call (and a short blip is not a long refusal for the strict callers).
    """
    global _SETTINGS_CACHE, _LAST_FETCH_TIME, _LAST_FAILURE, _LAST_FAILURE_TIME
    now = time.time()

    if (
        not force_refresh
        and _SETTINGS_CACHE is not None
        and (now - _LAST_FETCH_TIME < _CACHE_TTL_SECONDS)
    ):
        return _SETTINGS_CACHE

    failure: Optional[PlatformSettingsUnavailable] = None
    if not force_refresh and _LAST_FAILURE is not None and (now - _LAST_FAILURE_TIME < _NEGATIVE_CACHE_TTL_SECONDS):
        failure = _LAST_FAILURE
    else:
        raw: Optional[Dict[str, Any]] = None
        try:
            data = _read_stored_document(project_id)
            absent = data is None
            data = {} if absent else data
            raw = copy.deepcopy(data)
            # Purge the retired gemini-2.5 / 3.8-pro fallbacks (exact ids, RT F1). FD-4CI-b: a stored
            # max_output_tokens is no longer raised.
            if "models" in data and isinstance(data["models"], dict):
                if "fallback_models" in data["models"] and _is_model_id_list(data["models"]["fallback_models"]):
                    data["models"]["fallback_models"] = _purge_legacy_fallbacks(data["models"]["fallback_models"])
            if absent:
                logger.info("system_config/platform_settings not found in Firestore. Using baseline defaults.")
            loaded = PlatformSettings() if absent else platform_settings_from_stored(data)
        except PlatformSettingsUnavailable as e:
            failure = e
        except Exception as e:  # noqa: BLE001 - every parse failure of a present document is an invalid document
            errors = settings_validation_errors(e)
            failure = PlatformSettingsInvalid(f"stored system_config/platform_settings does not validate: "
                                              f"{_invalid_summary(e, errors)}", errors=errors, document=raw)
            failure.__cause__ = e
        if failure is None:
            _SETTINGS_CACHE, _LAST_FETCH_TIME = loaded, now
            _LAST_FAILURE, _LAST_FAILURE_TIME = None, 0.0
            return _SETTINGS_CACHE
        _LAST_FAILURE, _LAST_FAILURE_TIME = failure, now
        logger.error(f"{failure.code}: {failure.message}; strict callers fail closed, others use "
                     f"{'the last good settings' if _SETTINGS_CACHE is not None else 'the defaults'}.")

    if strict:
        raise failure.again() from failure
    if _SETTINGS_CACHE is not None:
        return _SETTINGS_CACHE
    defaults = PlatformSettings()
    # RT F2: these model fields were not read; a cascade does not lead with their code default
    _mark_model_defaults(defaults.models, ROLE_MODEL_FIELDS, ModelDefaultReason.SETTINGS_UNAVAILABLE)
    return defaults


def invalidate_settings_cache():
    """Forces immediate invalidation of the local memory cache (and of a remembered read failure)."""
    global _SETTINGS_CACHE, _LAST_FETCH_TIME, _LAST_FAILURE, _LAST_FAILURE_TIME
    _SETTINGS_CACHE = None
    _LAST_FETCH_TIME = 0.0
    _LAST_FAILURE = None
    _LAST_FAILURE_TIME = 0.0


# ------------------------------------------------------------------------------
# settings-toggles (FD-4AK Fable RT F5): readers of the three governance toggles. Every decision reads the settings
# strictly; when they cannot be established the decision is the safe one (no new run; approval required).
# ------------------------------------------------------------------------------
MAINTENANCE_MODE_CODE = "MAINTENANCE_MODE"
SETTINGS_UNAVAILABLE_CODE = "PLATFORM_SETTINGS_UNAVAILABLE"


def _settings_unknown_detail(err: Optional[BaseException], action: str) -> Dict[str, Any]:
    return {
        "code": getattr(err, "code", None) or SETTINGS_UNAVAILABLE_CODE,
        "message": (f"Platform settings could not be read or are invalid, so StackVend cannot tell whether "
                    f"maintenance mode is on: {action} was refused and nothing was started. Fix the settings "
                    "(Settings page) or retry when Firestore is reachable."),
        "errors": list(getattr(err, "errors", None) or []),
    }


def maintenance_refusal(settings: Any, action: str) -> Optional[Dict[str, Any]]:
    """None when a new run may start; else the typed detail for a 503. `settings` is what a strict read returned.
    maintenance_mode True -> code MAINTENANCE_MODE. Settings without a governance section (no settings module) or a
    non-boolean value are unknown -> refused (code PLATFORM_SETTINGS_UNAVAILABLE)."""
    gov = getattr(settings, "governance", None)
    value = getattr(gov, "maintenance_mode", None) if gov is not None else None
    if value is False:
        return None
    if value is True:
        return {
            "code": MAINTENANCE_MODE_CODE,
            "message": (f"Maintenance mode is on: StackVend is not starting new runs, so {action} was refused and "
                        "nothing was started. Runs already in progress continue; they are not stopped. Settings, "
                        "approvals and decommission still work. An admin can turn maintenance mode off on the "
                        "Settings page."),
            "errors": [],
        }
    return _settings_unknown_detail(None, action)


def new_run_refusal(action: str, *, project_id: Optional[str] = None, read: Any = None) -> Optional[Dict[str, Any]]:
    """Strict settings read + maintenance_refusal. `read` is the caller's get_platform_settings (default: this
    module's). An unreadable or invalid settings document refuses the new run (fail closed)."""
    reader = read if read is not None else get_platform_settings
    try:
        settings = reader(project_id=project_id, strict=True)
    except Exception as err:  # noqa: BLE001 - settings unknown: no new run
        logger.error(f"{getattr(err, 'code', SETTINGS_UNAVAILABLE_CODE)}: maintenance mode could not be evaluated "
                     f"for {action} ({type(err).__name__}: {err}); the new run is refused (fail closed).")
        return _settings_unknown_detail(err, action)
    return maintenance_refusal(settings, action)


def _strict_governance_flag(name: str, project_id: Optional[str], read: Any) -> Optional[bool]:
    """The boolean governance setting `name` from a strict read; None when it cannot be established."""
    reader = read if read is not None else get_platform_settings
    try:
        gov = getattr(reader(project_id=project_id, strict=True), "governance", None)
    except Exception as err:  # noqa: BLE001
        logger.error(f"{getattr(err, 'code', SETTINGS_UNAVAILABLE_CODE)}: governance.{name} could not be read "
                     f"({type(err).__name__}: {err}); the safe value applies (fail closed).")
        return None
    value = getattr(gov, name, None) if gov is not None else None
    return value if isinstance(value, bool) else None


def destructive_tf_requires_approval(*, project_id: Optional[str] = None, read: Any = None) -> bool:
    """governance.require_hitl_for_destructive_tf; True (approval required) when it cannot be established."""
    return _strict_governance_flag("require_hitl_for_destructive_tf", project_id, read) is not False


def compliance_advisories_block(*, project_id: Optional[str] = None, read: Any = None) -> bool:
    """governance.strict_compliance_gates, subordinate to plan_approval_policy (ST-3 RT F8): False when the switch is
    off or the policy is AUTONOMOUS_UNLESS_FAILED; True (advisories need a human) otherwise, and whenever either
    value cannot be established (one strict read)."""
    reader = read if read is not None else get_platform_settings
    try:
        gov = getattr(reader(project_id=project_id, strict=True), "governance", None)
    except Exception as err:  # noqa: BLE001
        logger.error(f"{getattr(err, 'code', SETTINGS_UNAVAILABLE_CODE)}: strict_compliance_gates could not be read "
                     f"({type(err).__name__}: {err}); advisories need a human (fail closed).")
        return True
    strict = getattr(gov, "strict_compliance_gates", None) if gov is not None else None
    policy = getattr(gov, "plan_approval_policy", None) if gov is not None else None
    if strict is False:
        return False
    if strict is True and isinstance(policy, str) and policy.strip().upper() == "AUTONOMOUS_UNLESS_FAILED":
        return False
    return True


def is_setting_int(v: Any) -> bool:
    """An int that is not a bool (FD-4CI-b reader check)."""
    return isinstance(v, int) and not isinstance(v, bool)


def is_setting_number(v: Any) -> bool:
    """An int or float that is not a bool (FD-4CI-b reader check)."""
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def strict_setting_value(section: str, name: str, fallback: Any, *, accept: Any = None,
                         project_id: Optional[str] = None, read: Any = None) -> Any:
    """FD-4CI-b: the stored `<section>.<name>` from a strict settings read (cached like every read). `fallback` -- the
    value the platform used before this setting was wired -- when the settings cannot be established (logged at
    ERROR with the settings error code) or the value is missing / fails `accept` (logged). A missing settings
    document is the schema default, as for every reader. Never raises."""
    reader = read if read is not None else get_platform_settings
    try:
        sec = getattr(reader(project_id=project_id, strict=True), section, None)
    except Exception as err:  # noqa: BLE001 - settings unknown: the pre-wiring behaviour
        logger.error(f"{getattr(err, 'code', SETTINGS_UNAVAILABLE_CODE)}: {section}.{name} could not be read "
                     f"({type(err).__name__}: {err}); using {fallback!r} (the platform default).")
        return fallback
    value = getattr(sec, name, None) if sec is not None else None
    try:
        usable = value is not None and (accept is None or bool(accept(value)))
    except Exception:  # noqa: BLE001 - an accept check that cannot judge the value refuses it
        usable = False
    if not usable:
        logger.error(f"{section}.{name} has no usable value ({type(value).__name__}); using {fallback!r}.")
        return fallback
    return value


def thinking_budget_of(settings: Any) -> int:
    """FD-4CI-b: models.default_thinking_budget of a settings object the caller already read (0 when absent or not an
    int in 1..2048). 0 = no thinking config is sent, as before the setting was read."""
    value = getattr(getattr(settings, "models", None), "default_thinking_budget", 0)
    return value if is_setting_int(value) and 0 < value <= 2048 else 0


def stored_setting_value(db: Any, section: str, name: str, fallback: Any, *, accept: Any = None) -> Any:
    """FD-4CI-b: `<section>.<name>` of system_config/platform_settings read through the caller's OWN Firestore client
    `db` (the Terraform server's pattern, FD-4AL `_settings_region`), validated by that section's settings model. A
    missing document is the schema default. No client (or not a Firestore snapshot), an unreadable or invalid
    document, or a value failing `accept` is `fallback` -- the pre-wiring behaviour -- logged. Never raises."""
    model = {"finops": FinOpsSettings, "orchestration": OrchestrationSettings, "models": AgentModelSettings,
             "governance": GovernanceSettings, "runtimes": RuntimeSettings}.get(section)
    if db is None or model is None:
        return fallback
    try:
        snap = db.collection("system_config").document("platform_settings").get()
        exists = getattr(snap, "exists", None)
        if exists is False:
            value = getattr(model(), name, None)
        else:
            data = snap.to_dict() if exists is True else None
            raw = data.get(section, {}) if isinstance(data, dict) else None
            if not isinstance(raw, dict):
                return fallback
            value = getattr(model(**raw), name, None)
    except Exception as err:  # noqa: BLE001 - unreadable / invalid: the pre-wiring behaviour
        logger.error(f"{section}.{name} could not be read ({type(err).__name__}: {err}); using {fallback!r}.")
        return fallback
    try:
        usable = value is not None and (accept is None or bool(accept(value)))
    except Exception:  # noqa: BLE001
        usable = False
    return value if usable else fallback


_WARNED_MODEL_DEFAULTS: set = set()


def get_model_cascade_for_agent(
    agent_name: str, project_id: Optional[str] = None
) -> List[str]:
    """
    Dynamically resolves primary and fallback Gemini model IDs for a given agent persona.
    Eliminates hardcoded model identifiers across agents and pulls directly from PlatformSettings.
    """
    try:
        settings = get_platform_settings(project_id=project_id)
        models_cfg = settings.models
        attr_name = f"{agent_name.lower().replace('-', '_')}_model"
        value = getattr(models_cfg, attr_name, None)
        env_model = os.getenv("GEMINI_MODEL")
        reason = model_default_reason(models_cfg, attr_name)
        if reason is not None:
            # RT F2: the field is a code default no one chose (settings unreadable / stored id reset): the model the
            # services ran before DEFAULT-MODEL-GEMINI-4-CARBON (the GEMINI_MODEL env) leads, never a silent switch
            primary = env_model or value or DEFAULT_PRIMARY_MODEL
            key = (reason, attr_name, primary)
            if key not in _WARNED_MODEL_DEFAULTS:
                _WARNED_MODEL_DEFAULTS.add(key)
                logger.warning(f"{reason.value}: models.{attr_name} holds its code default ({value!r}) because the "
                               f"settings were not read as stored; {agent_name} leads with {primary!r} "
                               f"({'GEMINI_MODEL' if env_model else 'the code default: GEMINI_MODEL is not set'})")
        else:
            primary = value or env_model or DEFAULT_PRIMARY_MODEL
        fallbacks = getattr(models_cfg, "fallback_models", None) or list(DEFAULT_FALLBACK_MODELS)
        cascade = [primary] + [m for m in fallbacks if m and m != primary]
        return list(dict.fromkeys(cascade))
    except Exception as e:
        logger.warning(f"Could not resolve dynamic model cascade for {agent_name} ({e}); using safe defaults.")
        env_model = os.getenv("GEMINI_MODEL") or DEFAULT_PRIMARY_MODEL
        return list(dict.fromkeys([env_model, *DEFAULT_FALLBACK_MODELS]))



# FD-4CI-b-R1: the branch every new workload used before Settings > Default GitHub Branch was applied.
DEFAULT_BRANCH_FALLBACK = "main"
_BRANCH_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/")


def is_branch_name(v: Any) -> bool:
    """FD-4CI-b-R1: a plain Git branch name the platform may write into a repository, a deploy workflow trigger and a
    pull-request base: 1..100 characters of letters, digits, '.', '_', '-', '/', no leading '-' or '/', no trailing
    '/' or '.', no '..', no empty path component, no component starting with '.' or ending in '.lock' (the
    `git check-ref-format` rules for that character set), and not exactly "HEAD" (git refuses it as a branch name;
    case-sensitive, as git). Structural check of the whole value; never a rewrite."""
    if not isinstance(v, str) or not 0 < len(v) <= 100 or not set(v) <= _BRANCH_NAME_CHARS:
        return False
    if v == "HEAD" or v[0] in "-/" or v[-1] in "/." or ".." in v:   # RT F1: git refuses the branch name HEAD
        return False
    return all(part and not part.startswith(".") and not part.endswith(".lock") for part in v.split("/"))


def default_branch_setting(*, project_id: Optional[str] = None, read: Any = None) -> str:
    """FD-4CI-b-R1: orchestration.default_branch for a NEW workload whose create request names no branch (strict
    read, cached). DEFAULT_BRANCH_FALLBACK ("main", the branch before the setting was applied) when the settings
    cannot be read or the stored value is not a plain branch name (is_branch_name), logged. Never raises."""
    return strict_setting_value("orchestration", "default_branch", DEFAULT_BRANCH_FALLBACK, accept=is_branch_name,
                                project_id=project_id, read=read)


def drive_folder_auto_discovery_enabled(*, project_id: Optional[str] = None, read: Any = None) -> bool:
    """OSS-D18: governance.drive_folder_auto_discovery; False (only explicitly configured folders are polled) unless
    it is exactly True on a strict read (unreadable / invalid settings keep it off, fail closed)."""
    return _strict_governance_flag("drive_folder_auto_discovery", project_id, read) is True


def iac_intent_generate_enabled(*, project_id: Optional[str] = None, read: Any = None) -> bool:
    """TI-3h: governance.iac_intent_generate; True only when it is exactly True on a strict read. A document without
    the key gets the default (GEN-DEFAULT, owner 10-26: True); an explicitly stored False stays False; unreadable /
    invalid settings keep it off (new workloads use today's HCL contract; never raises)."""
    return _strict_governance_flag("iac_intent_generate", project_id, read) is True


def freeze_new_workloads_enabled(*, project_id: Optional[str] = None, read: Any = None) -> bool:
    """FD-4CU: governance.freeze_new_workloads; True (a new workload starts with Code Freeze on) unless it is exactly
    False on a strict read. Missing -> the default (True); unreadable / invalid / not a bool -> True, logged (fail
    toward frozen). Never raises, so creating a workload never fails because of this read."""
    return _strict_governance_flag("freeze_new_workloads", project_id, read) is not False
