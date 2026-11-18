"""
Project Castor: Compliance MCP Tool Server - FastAPI Microservice
Exposes Assured Workloads inspection, specification compliance detection, and HCL compliance evaluation endpoints.
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import logging
import os
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator
from service import (
    COMPLIANCE_CONTRACT_VERSION,
    ComplianceService,
    InvalidComplianceProfile,
    ProfileRefused,
    parse_requested_profile,
    plan_gate,
)
from fastapi.responses import JSONResponse

logger = logging.getLogger("mcp-compliance-server")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="StackVend Compliance MCP Tool Server",
    description="Assured Workloads Inspector and Enterprise Regulatory Policy Engine",
    version="1.0.0",
)

service = ComplianceService(project_id=os.getenv("PROJECT_ID", ""))


@app.exception_handler(ProfileRefused)
def _profile_refused(_request, exc: ProfileRefused):
    """Owner decisions 10-18 (CP-8 / CP-10): the profile cannot be decided -> typed 422 (never a silent STANDARD)."""
    return JSONResponse(status_code=422, content={"detail": {"error_class": exc.error_class, "detail": exc.detail}})


class InspectFolderRequest(BaseModel):
    folder_id: Optional[str] = Field(default="", description="GCP Folder ID e.g. folders/123456")
    spec_text: Optional[str] = Field(default="", description="Natural language specification text")
    # compliance-profile-explicit: the ONLY non-folder source of the profile. Exactly one of plan_gate.KNOWN_PROFILES,
    # or absent/null/"" (-> STANDARD, profile_source DEFAULT_STANDARD). Anything else is a 422.
    compliance_profile: Optional[str] = Field(default=None, description="Explicit compliance profile")

    @field_validator("compliance_profile")
    @classmethod
    def _exact_profile(cls, value: Optional[str]) -> Optional[str]:
        try:
            return parse_requested_profile(value)
        except InvalidComplianceProfile as e:
            raise ValueError(f"{InvalidComplianceProfile.error_class}: {e}") from e


class InspectFolderResponse(BaseModel):
    # Contract v2 (lane 17 PR-1a, compliance bundle): the gateway requires contract_version >= 2, enable_direct_iap and
    # allow_unauthenticated, and fails closed otherwise. Required here too, so the server can never emit a v1 shape.
    # Contract v3 (compliance-profile-explicit): profile_source / requested_profile / profile_suggestions.
    contract_version: int
    intent_source: str
    enable_direct_iap: bool
    profile: str
    profile_source: str
    requested_profile: Optional[str]
    profile_suggestions: List[Dict[str, Any]]
    is_regulated: bool
    is_assured_workload: bool
    compliance_regime: str
    requires_cmek: bool
    requires_audit_logging: bool
    allowed_regions: List[str]
    mandated_tasks: List[Dict[str, Any]]
    description: str
    domain_restricted_sharing: bool = Field(default=False)
    allowed_domains: List[str] = Field(default_factory=list)
    allow_unauthenticated: bool = Field(default=True)
    enforce_private_ingress: bool = Field(default=False)
    private_ingress_sources: List[str] = Field(default_factory=list)  # PRIVATE-INGRESS-EARLY-STOP (additive report)
    private_ingress_spec_terms: List[str] = Field(default_factory=list)
    disallow_vm_external_ip: bool = Field(default=False)
    disallow_default_network: bool = Field(default=False)
    require_os_login: bool = Field(default=False)
    require_shielded_vm: bool = Field(default=False)
    enforce_uniform_bucket_level_access: bool = Field(default=False)
    enforce_public_access_prevention: bool = Field(default=False)
    disable_sa_key_creation: bool = Field(default=False)
    restrict_public_sql: bool = Field(default=False)
    policy_matrix: Dict[str, Any] = Field(default_factory=dict)


class EvaluateHclRequest(BaseModel):
    hcl_files: Dict[str, str] = Field(description="Dictionary mapping filename to HCL content")
    profile: str = Field(default="STANDARD", description="Compliance profile to enforce")
    ingress: Dict[str, Any] = Field(default_factory=dict, description="Stored compliance decision ingress flags")


class EvaluateHclResponse(BaseModel):
    compliant: bool
    violations: List[str]
    summary: str
    # Lane 14 PR-0: parser-based engine. `unverified` = values only the plan gate can decide (e.g. `var.region`);
    # `error_class` = PARSE_ERROR / UNKNOWN_PROFILE / PARSER_UNAVAILABLE / COMPLIANCE_VIOLATION / None.
    unverified: List[str] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    error_class: Optional[str] = None


class EvaluatePlanRequest(BaseModel):
    """Lane 14 PR-0 plan gate. `plan` = `tofu show -json <planfile>`; `profile` / `ingress` / `org_allowed_locations`
    = the workload's stored compliance decision (`workloads/{pid}.compliance_decision`), read by the caller."""
    gate_contract_version: int = Field(default=plan_gate.GATE_CONTRACT_VERSION)
    product_id: str = Field(default="")
    trace_id: str = Field(default="")
    profile: str
    ingress: Dict[str, Any] = Field(default_factory=dict)
    org_allowed_locations: List[str] = Field(default_factory=list)
    plan: Dict[str, Any]


class EvaluatePlanResponse(BaseModel):
    gate_contract_version: int
    decision: str
    error_class: Optional[str]
    profile: str
    requirements: Dict[str, Any]
    checks_run: List[str]
    violations: List[Dict[str, Any]]
    resources_evaluated: int
    location_table_version: str
    detail: str


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "mcp-compliance-server",
        "contract_version": COMPLIANCE_CONTRACT_VERSION,
        "gate_contract_version": plan_gate.GATE_CONTRACT_VERSION,
        "release": release_info.current_release(),  # FD-7C P3a: read-only, from this build's release.json
    }


@app.post("/harvest-policies")
def harvest_policies(req: InspectFolderRequest):
    """Dynamically harvests all GCP Organization Policies on the target folder."""
    return service.harvest_folder_policies(req.folder_id or "")


@app.post("/inspect-folder", response_model=InspectFolderResponse)
def inspect_folder(req: InspectFolderRequest):
    """
    Inspects target GCP folder and spec text. If standard, completes in <50ms.
    The profile is the folder's Assured Workloads regime, else the explicit `compliance_profile`, else STANDARD
    (contract v3; spec words only produce advisory `profile_suggestions`). Org policies and the ingress intent can
    still make the answer regulated. Contract v2: also derives the spec's ingress intent (Direct IAP, domain
    restriction, private ingress, no unauthenticated access) and combines it with org policy, most restrictive wins
    (lane 17 R-3; one implementation in `ComplianceService.inspect_folder`).
    """
    return InspectFolderResponse(**service.inspect_folder(
        req.folder_id or "", req.spec_text or "", requested_profile=req.compliance_profile))


@app.post("/evaluate-hcl", response_model=EvaluateHclResponse)
def evaluate_hcl(req: EvaluateHclRequest):
    """Advisory pre-commit check: parses the HCL (python-hcl2) and runs the plan gate's typed check table. The plan
    gate (`/evaluate-plan`) is the enforcing point."""
    return EvaluateHclResponse(**service.evaluate_hcl_compliance(req.hcl_files, req.profile, req.ingress))


@app.post("/evaluate-plan", response_model=EvaluatePlanResponse)
def evaluate_plan(req: EvaluatePlanRequest):
    """Lane 14 PR-0 (FD-4S): the compliance enforcement gate, called after `tofu plan` and before every apply.
    PASS -> apply may proceed; VIOLATION / REFUSED -> the caller refuses the apply (fail closed)."""
    if req.gate_contract_version != plan_gate.GATE_CONTRACT_VERSION:
        raise HTTPException(
            status_code=422,
            detail=f"gate_contract_version {req.gate_contract_version} != {plan_gate.GATE_CONTRACT_VERSION}",
        )
    result = service.evaluate_plan_compliance(req.plan, req.profile, req.ingress, req.org_allowed_locations)
    logger.info(
        f"/evaluate-plan product={req.product_id} trace={req.trace_id} profile={req.profile} "
        f"decision={result['decision']} error_class={result['error_class']} violations={len(result['violations'])}"
    )
    return EvaluatePlanResponse(**result)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
